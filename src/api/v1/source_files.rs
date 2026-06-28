use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD as Base64Engine;
use base64::Engine as _;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Component, Path as FsPath, PathBuf};
use uuid::Uuid;

use crate::api::v1::admin::require_service_admin;
use crate::error::{status_for_app_error, AppError, ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT};
use crate::http_api::{json_error, json_error_with_details};
use crate::repo_encryption::{repo_encryption_domain_id, RepoEncryptionConfig};
use crate::search::AppState;
use crate::state_layout::repo_state_root_from_state_dir;

const SOURCE_FILE_PURPOSE: &str = "source_file_content_base64";
const MAX_SOURCE_FILE_BATCH_SIZE: usize = 50;
const MAX_SOURCE_FILE_BYTES: usize = 250 * 1024 * 1024;

#[derive(Debug, Deserialize)]
pub struct AdminSourceFileStoreRequest {
    files: Vec<AdminSourceFileInput>,
}

#[derive(Debug, Deserialize)]
pub struct AdminSourceFileInput {
    #[serde(default)]
    file_id: Option<String>,
    original_name: String,
    #[serde(default)]
    mime_type: Option<String>,
    content_base64: String,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    source_path: Option<String>,
    #[serde(default)]
    metadata_json: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct AdminSourceFileListQuery {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    source_prefix: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AdminSourceFileStoreResponse {
    repo_id: String,
    count: usize,
    files: Vec<AdminSourceFileItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminSourceFileItem {
    file_id: String,
    original_name: String,
    mime_type: String,
    size_bytes: u64,
    sha256: String,
    source_path: Option<String>,
    metadata_json: Option<Value>,
    stored_at_ms: i64,
    encrypted: bool,
    encryption_key_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AdminSourceFileListResponse {
    repo_id: String,
    count: usize,
    total: usize,
    files: Vec<AdminSourceFileItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum SourceFileContentEncoding {
    Base64,
    RepoEncryptedBase64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SourceFileRecord {
    file_id: String,
    original_name: String,
    mime_type: String,
    size_bytes: u64,
    sha256: String,
    source_path: Option<String>,
    metadata_json: Option<Value>,
    stored_at_ms: i64,
    encrypted: bool,
    encryption_key_id: Option<String>,
    content_encoding: SourceFileContentEncoding,
    content: String,
}

struct SourceFileContent {
    item: AdminSourceFileItem,
    bytes: Vec<u8>,
}

pub async fn admin_source_files_store_handler(
    State(state): State<AppState>,
    Path(repo_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<AdminSourceFileStoreRequest>,
) -> Response {
    if let Err(response) =
        require_service_admin(&state, &headers, "/v1/admin/repos/{repo_id}/source-files")
    {
        return response;
    }
    if request.files.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "files must not be empty",
        );
    }
    if request.files.len() > MAX_SOURCE_FILE_BATCH_SIZE {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            format!("files exceeds the maximum batch size of {MAX_SOURCE_FILE_BATCH_SIZE}"),
        );
    }
    let repo = match resolve_source_file_repo(&state, &headers, &repo_id) {
        Ok(repo) => repo,
        Err(response) => return response,
    };
    let store_dir = source_files_store_dir(repo.indexer.state_dir());
    let repo_root = repo.indexer.repo_root().to_path_buf();
    let repo_encryption = repo.indexer.config().repo_encryption().clone();
    let mut files = Vec::with_capacity(request.files.len());
    for input in request.files {
        match store_source_file(&store_dir, &repo_root, &repo_encryption, input).await {
            Ok(item) => files.push(item),
            Err(err) => return app_error_to_response(err),
        }
    }
    Json(AdminSourceFileStoreResponse {
        repo_id: repo.repo_id.clone(),
        count: files.len(),
        files,
    })
    .into_response()
}

pub async fn admin_source_files_list_handler(
    State(state): State<AppState>,
    Path(repo_id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<AdminSourceFileListQuery>,
) -> Response {
    if let Err(response) =
        require_service_admin(&state, &headers, "/v1/admin/repos/{repo_id}/source-files")
    {
        return response;
    }
    let repo = match resolve_source_file_repo(&state, &headers, &repo_id) {
        Ok(repo) => repo,
        Err(response) => return response,
    };
    let store_dir = source_files_store_dir(repo.indexer.state_dir());
    match list_source_files(&store_dir, query).await {
        Ok((total, files)) => Json(AdminSourceFileListResponse {
            repo_id: repo.repo_id.clone(),
            count: files.len(),
            total,
            files,
        })
        .into_response(),
        Err(err) => app_error_to_response(err),
    }
}

pub async fn admin_source_file_metadata_handler(
    State(state): State<AppState>,
    Path((repo_id, file_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = require_service_admin(
        &state,
        &headers,
        "/v1/admin/repos/{repo_id}/source-files/{file_id}",
    ) {
        return response;
    }
    let repo = match resolve_source_file_repo(&state, &headers, &repo_id) {
        Ok(repo) => repo,
        Err(response) => return response,
    };
    let store_dir = source_files_store_dir(repo.indexer.state_dir());
    match load_source_file_record(&store_dir, &file_id).await {
        Ok(record) => Json(record.to_item()).into_response(),
        Err(err) => app_error_to_response(err),
    }
}

pub async fn admin_source_file_content_handler(
    State(state): State<AppState>,
    Path((repo_id, file_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = require_service_admin(
        &state,
        &headers,
        "/v1/admin/repos/{repo_id}/source-files/{file_id}/content",
    ) {
        return response;
    }
    let repo = match resolve_source_file_repo(&state, &headers, &repo_id) {
        Ok(repo) => repo,
        Err(response) => return response,
    };
    let store_dir = source_files_store_dir(repo.indexer.state_dir());
    let repo_root = repo.indexer.repo_root().to_path_buf();
    let repo_encryption = repo.indexer.config().repo_encryption().clone();
    match load_source_file_content(&store_dir, &repo_root, &repo_encryption, &file_id).await {
        Ok(content) => source_file_content_response(content),
        Err(err) => app_error_to_response(err),
    }
}

fn resolve_source_file_repo(
    state: &AppState,
    headers: &HeaderMap,
    repo_id: &str,
) -> Result<crate::search::RepoContext, Response> {
    let repo_id = repo_id.trim();
    if repo_id.is_empty() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "repo_id is required",
        ));
    }
    crate::http_api::resolve_repo_context(state, headers, None, Some(repo_id), true)
        .map_err(crate::http_api::repo_error_response)
}

fn source_files_store_dir(state_dir: &FsPath) -> PathBuf {
    repo_state_root_from_state_dir(state_dir)
        .join("source_files")
        .join("records")
}

async fn store_source_file(
    store_dir: &FsPath,
    repo_root: &FsPath,
    repo_encryption: &RepoEncryptionConfig,
    input: AdminSourceFileInput,
) -> Result<AdminSourceFileItem, AppError> {
    let file_id = match input.file_id {
        Some(file_id) => safe_source_file_id(&file_id)?,
        None => Uuid::new_v4().to_string(),
    };
    let original_name = sanitize_original_name(&input.original_name);
    let mime_type = input
        .mime_type
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "application/octet-stream".to_string());
    let source_path = match input.source_path {
        Some(path) => Some(safe_source_path(&path)?),
        None => None,
    };
    let bytes = Base64Engine
        .decode(input.content_base64.trim())
        .map_err(|err| {
            AppError::new(
                ERR_INVALID_ARGUMENT,
                format!("content_base64 is invalid: {err}"),
            )
        })?;
    if bytes.len() > MAX_SOURCE_FILE_BYTES {
        return Err(AppError::new(
            ERR_INVALID_ARGUMENT,
            format!("source file exceeds the maximum size of {MAX_SOURCE_FILE_BYTES} bytes"),
        ));
    }
    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    if let Some(expected) = input
        .sha256
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if !expected.eq_ignore_ascii_case(&sha256) {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "content_base64 sha256 does not match provided sha256",
            ));
        }
    }
    let base64_content = Base64Engine.encode(&bytes);
    let (content_encoding, content, encrypted, encryption_key_id) = if repo_encryption.is_enabled()
    {
        let key = repo_encryption.require_key().map_err(|err| {
            AppError::new(
                ERR_INVALID_ARGUMENT,
                format!("repo encryption key is required to store source file: {err}"),
            )
        })?;
        let domain_id = repo_encryption_domain_id(repo_root);
        let protected = repo_encryption
            .protect_text(
                &key,
                &domain_id,
                &file_id,
                SOURCE_FILE_PURPOSE,
                &base64_content,
            )
            .map_err(|err| {
                AppError::new(
                    ERR_INVALID_ARGUMENT,
                    format!("failed to encrypt source file content: {err}"),
                )
            })?;
        (
            SourceFileContentEncoding::RepoEncryptedBase64,
            protected,
            true,
            Some(key.key_id),
        )
    } else {
        (
            SourceFileContentEncoding::Base64,
            base64_content,
            false,
            None,
        )
    };
    let record = SourceFileRecord {
        file_id,
        original_name,
        mime_type,
        size_bytes: bytes.len() as u64,
        sha256,
        source_path,
        metadata_json: input.metadata_json,
        stored_at_ms: Utc::now().timestamp_millis(),
        encrypted,
        encryption_key_id,
        content_encoding,
        content,
    };
    tokio::fs::create_dir_all(store_dir).await.map_err(|err| {
        AppError::new(
            ERR_INTERNAL_ERROR,
            format!("failed to create source file store: {err}"),
        )
    })?;
    let record_path = source_file_record_path(store_dir, &record.file_id)?;
    let payload = serde_json::to_vec_pretty(&record).map_err(|err| {
        AppError::new(
            ERR_INTERNAL_ERROR,
            format!("failed to serialize source file record: {err}"),
        )
    })?;
    tokio::fs::write(&record_path, payload)
        .await
        .map_err(|err| {
            AppError::new(
                ERR_INTERNAL_ERROR,
                format!("failed to write source file record: {err}"),
            )
        })?;
    Ok(record.to_item())
}

async fn list_source_files(
    store_dir: &FsPath,
    query: AdminSourceFileListQuery,
) -> Result<(usize, Vec<AdminSourceFileItem>), AppError> {
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let offset = query.offset.unwrap_or(0);
    let source_prefix = query
        .source_prefix
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(safe_source_path)
        .transpose()?;
    let mut records = Vec::new();
    let mut dir = match tokio::fs::read_dir(store_dir).await {
        Ok(dir) => dir,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok((0, Vec::new())),
        Err(err) => {
            return Err(AppError::new(
                ERR_INTERNAL_ERROR,
                format!("failed to read source file store: {err}"),
            ))
        }
    };
    while let Some(entry) = dir.next_entry().await.map_err(|err| {
        AppError::new(
            ERR_INTERNAL_ERROR,
            format!("failed to read source file store entry: {err}"),
        )
    })? {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let record = load_source_file_record_path(&path).await?;
        if let Some(prefix) = source_prefix.as_deref() {
            if !record
                .source_path
                .as_deref()
                .is_some_and(|source_path| source_path.starts_with(prefix))
            {
                continue;
            }
        }
        records.push(record.to_item());
    }
    records.sort_by(|first, second| {
        second
            .stored_at_ms
            .cmp(&first.stored_at_ms)
            .then_with(|| first.original_name.cmp(&second.original_name))
    });
    let total = records.len();
    Ok((
        total,
        records.into_iter().skip(offset).take(limit).collect(),
    ))
}

async fn load_source_file_content(
    store_dir: &FsPath,
    repo_root: &FsPath,
    repo_encryption: &RepoEncryptionConfig,
    file_id: &str,
) -> Result<SourceFileContent, AppError> {
    let record = load_source_file_record(store_dir, file_id).await?;
    let encoded = match record.content_encoding {
        SourceFileContentEncoding::Base64 => record.content.clone(),
        SourceFileContentEncoding::RepoEncryptedBase64 => {
            let key = repo_encryption.require_key().map_err(|err| {
                AppError::new(
                    ERR_INVALID_ARGUMENT,
                    format!("repo encryption key is required to read source file: {err}"),
                )
            })?;
            let domain_id = repo_encryption_domain_id(repo_root);
            repo_encryption
                .unprotect_text(
                    &key,
                    &domain_id,
                    &record.file_id,
                    SOURCE_FILE_PURPOSE,
                    &record.content,
                )
                .map_err(|err| {
                    AppError::new(
                        ERR_INVALID_ARGUMENT,
                        format!("failed to decrypt source file content: {err}"),
                    )
                })?
        }
    };
    let bytes = Base64Engine.decode(encoded.trim()).map_err(|err| {
        AppError::new(
            ERR_INVALID_ARGUMENT,
            format!("stored source file content is invalid: {err}"),
        )
    })?;
    Ok(SourceFileContent {
        item: record.to_item(),
        bytes,
    })
}

async fn load_source_file_record(
    store_dir: &FsPath,
    file_id: &str,
) -> Result<SourceFileRecord, AppError> {
    let file_id = safe_source_file_id(file_id)?;
    let path = source_file_record_path(store_dir, &file_id)?;
    load_source_file_record_path(&path).await
}

async fn load_source_file_record_path(path: &FsPath) -> Result<SourceFileRecord, AppError> {
    let payload = tokio::fs::read(path).await.map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            AppError::new(ERR_INVALID_ARGUMENT, "source file not found")
        } else {
            AppError::new(
                ERR_INTERNAL_ERROR,
                format!("failed to read source file record: {err}"),
            )
        }
    })?;
    serde_json::from_slice(&payload).map_err(|err| {
        AppError::new(
            ERR_INTERNAL_ERROR,
            format!("failed to parse source file record: {err}"),
        )
    })
}

fn source_file_record_path(store_dir: &FsPath, file_id: &str) -> Result<PathBuf, AppError> {
    Ok(store_dir.join(format!("{}.json", safe_source_file_id(file_id)?)))
}

fn safe_source_file_id(raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 128 {
        return Err(AppError::new(
            ERR_INVALID_ARGUMENT,
            "source file id must be between 1 and 128 characters",
        ));
    }
    if trimmed.starts_with('.') {
        return Err(AppError::new(
            ERR_INVALID_ARGUMENT,
            "source file id must not start with a dot",
        ));
    }
    if !trimmed
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(AppError::new(
            ERR_INVALID_ARGUMENT,
            "source file id contains invalid characters",
        ));
    }
    Ok(trimmed.to_string())
}

fn safe_source_path(raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AppError::new(
            ERR_INVALID_ARGUMENT,
            "source_path is required",
        ));
    }
    let path = FsPath::new(trimmed);
    if path.is_absolute() {
        return Err(AppError::new(
            ERR_INVALID_ARGUMENT,
            "source_path must be relative",
        ));
    }
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => parts.push(value.to_string_lossy().to_string()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(AppError::new(
                    ERR_INVALID_ARGUMENT,
                    "source_path must not escape the repository",
                ))
            }
        }
    }
    if parts.is_empty() {
        return Err(AppError::new(
            ERR_INVALID_ARGUMENT,
            "source_path is required",
        ));
    }
    Ok(parts.join("/"))
}

fn sanitize_original_name(raw: &str) -> String {
    let trimmed = raw.trim();
    let file_name = FsPath::new(trimmed)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(trimmed);
    let sanitized = file_name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | ' ') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim()
        .trim_matches('.')
        .to_string();
    if sanitized.is_empty() {
        "source-file".to_string()
    } else {
        sanitized.chars().take(191).collect()
    }
}

fn source_file_content_response(content: SourceFileContent) -> Response {
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content.item.mime_type.as_str())
        .header(header::CONTENT_LENGTH, content.bytes.len().to_string())
        .header(
            header::CONTENT_DISPOSITION,
            format!(
                "attachment; filename=\"{}\"",
                content_disposition_filename(&content.item.original_name)
            ),
        )
        .header("x-docdex-source-file-id", content.item.file_id.as_str())
        .header("x-docdex-source-file-sha256", content.item.sha256.as_str());
    if let Ok(value) = HeaderValue::from_str(&content.item.original_name) {
        builder = builder.header("x-docdex-source-file-name", value);
    }
    builder.body(Body::from(content.bytes)).unwrap_or_else(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            "failed to build source file response",
        )
    })
}

fn content_disposition_filename(name: &str) -> String {
    name.chars()
        .map(|ch| match ch {
            '"' | '\\' | '\r' | '\n' => '_',
            ch if ch.is_ascii_graphic() || ch == ' ' => ch,
            _ => '_',
        })
        .collect()
}

fn app_error_to_response(err: AppError) -> Response {
    let status = status_for_app_error(err.code);
    match err.details {
        Some(details) => json_error_with_details(status, err.code, err.message, details),
        None => json_error(status, err.code, err.message),
    }
}

impl SourceFileRecord {
    fn to_item(&self) -> AdminSourceFileItem {
        AdminSourceFileItem {
            file_id: self.file_id.clone(),
            original_name: self.original_name.clone(),
            mime_type: self.mime_type.clone(),
            size_bytes: self.size_bytes,
            sha256: self.sha256.clone(),
            source_path: self.source_path.clone(),
            metadata_json: self.metadata_json.clone(),
            stored_at_ms: self.stored_at_ms,
            encrypted: self.encrypted,
            encryption_key_id: self.encryption_key_id.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo_encryption::{RepoEncryptionMode, DEFAULT_REPO_ENCRYPTION_KEY_ENV};
    use crate::setup::test_support::ENV_LOCK;

    const TEST_KEY: &str = "01234567890123456789012345678901";

    #[tokio::test]
    async fn source_file_store_round_trips_encrypted_content_without_plaintext_record() {
        let _guard = ENV_LOCK.lock();
        std::env::set_var(DEFAULT_REPO_ENCRYPTION_KEY_ENV, TEST_KEY);
        let temp = tempfile::TempDir::new().expect("tempdir");
        let repo_root = temp.path().join("repo");
        let store_dir = temp
            .path()
            .join("state")
            .join("source_files")
            .join("records");
        tokio::fs::create_dir_all(&repo_root)
            .await
            .expect("repo root");
        let mut repo_encryption = RepoEncryptionConfig {
            encryption_mode: RepoEncryptionMode::ApplicationManagedEncryption,
            ..RepoEncryptionConfig::default()
        };
        repo_encryption.apply_defaults();
        let bytes = b"private business plan";
        let item = store_source_file(
            &store_dir,
            &repo_root,
            &repo_encryption,
            AdminSourceFileInput {
                file_id: Some("file-1".to_string()),
                original_name: "business-plan.txt".to_string(),
                mime_type: Some("text/plain".to_string()),
                content_base64: Base64Engine.encode(bytes),
                sha256: None,
                source_path: Some("okacam/business-analytics/file-1.txt".to_string()),
                metadata_json: Some(serde_json::json!({ "tenant": "wodo" })),
            },
        )
        .await
        .expect("store");

        assert!(item.encrypted);
        let raw_record = tokio::fs::read_to_string(store_dir.join("file-1.json"))
            .await
            .expect("record");
        assert!(!raw_record.contains("private business plan"));
        assert!(raw_record.contains("repo_encrypted_base64"));

        let content = load_source_file_content(&store_dir, &repo_root, &repo_encryption, "file-1")
            .await
            .expect("content");
        assert_eq!(content.bytes, bytes);
        assert_eq!(content.item.original_name, "business-plan.txt");
        std::env::remove_var(DEFAULT_REPO_ENCRYPTION_KEY_ENV);
    }

    #[test]
    fn source_file_paths_reject_escape_attempts() {
        assert!(safe_source_path("../secret.txt").is_err());
        assert!(safe_source_path("/secret.txt").is_err());
        assert_eq!(
            safe_source_path("okacam/./docs/file.pdf").unwrap(),
            "okacam/docs/file.pdf"
        );
    }
}
