use axum::body::Body;
use axum::extract::multipart::Field;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD as Base64Engine;
use base64::Engine as _;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::File as StdFile;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Component, Path as FsPath, PathBuf};
use uuid::Uuid;
use zip::read::ZipFile;
use zip::ZipArchive;

use crate::api::v1::admin::require_service_admin;
use crate::error::{status_for_app_error, AppError, ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT};
use crate::http_api::{json_error, json_error_with_details};
use crate::repo_encryption::{repo_encryption_domain_id, RepoEncryptionConfig};
use crate::search::AppState;
use crate::state_layout::repo_state_root_from_state_dir;

const SOURCE_FILE_PURPOSE: &str = "source_file_content_base64";
const SOURCE_FILE_BLOB_PURPOSE: &str = "source_file_content_blob";
const SOURCE_FILE_ENCRYPTED_BLOB_MAGIC: &[u8] = b"docdex-source-file-encrypted-blob:v1\n";
const SOURCE_FILE_BLOB_CHUNK_BYTES: usize = 4 * 1024 * 1024;
const MAX_SOURCE_FILE_BATCH_SIZE: usize = 50;
const MAX_SOURCE_FILE_BYTES: usize = 250 * 1024 * 1024;
pub const MAX_SOURCE_FILE_MULTIPART_BYTES: usize = 5 * 1024 * 1024 * 1024;
pub const SOURCE_FILE_MULTIPART_BODY_LIMIT_BYTES: usize =
    MAX_SOURCE_FILE_MULTIPART_BYTES + 16 * 1024 * 1024;
const MAX_SOURCE_ARCHIVE_ENTRIES: usize = 5000;
const MAX_SOURCE_ARCHIVE_TOTAL_UNCOMPRESSED_BYTES: u64 = 20 * 1024 * 1024 * 1024;

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

#[derive(Debug, Default, Deserialize)]
pub struct AdminSourceFileMultipartMetadata {
    #[serde(default)]
    file_id: Option<String>,
    #[serde(default)]
    original_name: Option<String>,
    #[serde(default)]
    mime_type: Option<String>,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    source_path: Option<String>,
    #[serde(default)]
    metadata_json: Option<Value>,
    #[serde(default)]
    extract_archives: Option<bool>,
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
    Blob,
    RepoEncryptedBlob,
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

struct MultipartSourceFile {
    path: PathBuf,
    original_name: Option<String>,
    mime_type: Option<String>,
    size_bytes: u64,
    sha256: String,
}

struct SourceFilePathInput {
    file_id: Option<String>,
    original_name: String,
    mime_type: Option<String>,
    path: PathBuf,
    size_bytes: u64,
    sha256: Option<String>,
    source_path: Option<String>,
    metadata_json: Option<Value>,
}

struct StoredSourceFileRecord {
    item: AdminSourceFileItem,
    record: SourceFileRecord,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedBlobHeader {
    version: u8,
    key_id: String,
    chunk_size: usize,
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

pub async fn admin_source_files_upload_handler(
    State(state): State<AppState>,
    Path(repo_id): Path<String>,
    headers: HeaderMap,
    multipart: Multipart,
) -> Response {
    if let Err(response) = require_service_admin(
        &state,
        &headers,
        "/v1/admin/repos/{repo_id}/source-files/upload",
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
    match store_multipart_source_file(&store_dir, &repo_root, &repo_encryption, multipart).await {
        Ok(files) => Json(AdminSourceFileStoreResponse {
            repo_id: repo.repo_id.clone(),
            count: files.len(),
            files,
        })
        .into_response(),
        Err(err) => app_error_to_response(err),
    }
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

fn source_files_root_dir(store_dir: &FsPath) -> PathBuf {
    store_dir
        .parent()
        .map(FsPath::to_path_buf)
        .unwrap_or_else(|| store_dir.to_path_buf())
}

fn source_files_blob_dir(store_dir: &FsPath) -> PathBuf {
    source_files_root_dir(store_dir).join("blobs")
}

fn source_files_temp_dir(store_dir: &FsPath) -> PathBuf {
    source_files_root_dir(store_dir).join("tmp")
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
    write_source_file_record(store_dir, &record).await?;
    Ok(record.to_item())
}

async fn store_multipart_source_file(
    store_dir: &FsPath,
    repo_root: &FsPath,
    repo_encryption: &RepoEncryptionConfig,
    mut multipart: Multipart,
) -> Result<Vec<AdminSourceFileItem>, AppError> {
    let mut metadata = AdminSourceFileMultipartMetadata::default();
    let mut upload: Option<MultipartSourceFile> = None;
    while let Some(field) = multipart_next_field(&mut multipart).await? {
        let name = field.name().unwrap_or_default().to_string();
        match name.as_str() {
            "file" | "files" => {
                if upload.is_some() {
                    return Err(AppError::new(
                        ERR_INVALID_ARGUMENT,
                        "multipart source-file upload accepts exactly one file",
                    ));
                }
                upload = Some(save_multipart_source_file_field(store_dir, field).await?);
            }
            "metadata" => {
                metadata = parse_multipart_metadata(&read_multipart_text(field).await?)?;
            }
            "metadata_json" => {
                metadata.metadata_json = Some(parse_multipart_json_value(
                    &read_multipart_text(field).await?,
                )?);
            }
            "file_id" => metadata.file_id = Some(read_multipart_text(field).await?),
            "original_name" => metadata.original_name = Some(read_multipart_text(field).await?),
            "mime_type" => metadata.mime_type = Some(read_multipart_text(field).await?),
            "sha256" => metadata.sha256 = Some(read_multipart_text(field).await?),
            "source_path" => metadata.source_path = Some(read_multipart_text(field).await?),
            "extract_archives" => {
                metadata.extract_archives =
                    Some(parse_bool_field(&read_multipart_text(field).await?));
            }
            _ => {}
        }
    }
    let upload = upload.ok_or_else(|| {
        AppError::new(
            ERR_INVALID_ARGUMENT,
            "multipart source-file upload requires a file field",
        )
    })?;
    let mut cleanup_paths = vec![upload.path.clone()];
    let original_name = metadata
        .original_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or(upload.original_name.clone())
        .ok_or_else(|| AppError::new(ERR_INVALID_ARGUMENT, "original_name is required"))?;
    let mime_type = metadata
        .mime_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or(upload.mime_type.clone());
    let expected_sha = metadata
        .sha256
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(expected) = expected_sha {
        if !expected.eq_ignore_ascii_case(&upload.sha256) {
            remove_files_best_effort(&cleanup_paths).await;
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "multipart source file sha256 does not match provided sha256",
            ));
        }
    }
    let stored = store_source_file_from_path(
        store_dir,
        repo_root,
        repo_encryption,
        SourceFilePathInput {
            file_id: metadata.file_id,
            original_name,
            mime_type,
            path: upload.path.clone(),
            size_bytes: upload.size_bytes,
            sha256: Some(upload.sha256.clone()),
            source_path: metadata.source_path,
            metadata_json: metadata.metadata_json,
        },
    )
    .await;
    let stored = match stored {
        Ok(stored) => stored,
        Err(err) => {
            remove_files_best_effort(&cleanup_paths).await;
            return Err(err);
        }
    };
    let mut items = vec![stored.item.clone()];
    if metadata.extract_archives.unwrap_or(false)
        && is_zip_archive(&stored.record.original_name, &stored.record.mime_type)
    {
        match extract_zip_archive_source_files(
            store_dir,
            repo_root,
            repo_encryption,
            &upload.path,
            &stored.record,
            &mut cleanup_paths,
        )
        .await
        {
            Ok(mut extracted) => items.append(&mut extracted),
            Err(err) => {
                remove_files_best_effort(&cleanup_paths).await;
                return Err(err);
            }
        }
    }
    remove_files_best_effort(&cleanup_paths).await;
    Ok(items)
}

async fn store_source_file_from_path(
    store_dir: &FsPath,
    repo_root: &FsPath,
    repo_encryption: &RepoEncryptionConfig,
    input: SourceFilePathInput,
) -> Result<StoredSourceFileRecord, AppError> {
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
    if input.size_bytes as usize > MAX_SOURCE_FILE_MULTIPART_BYTES {
        return Err(AppError::new(
            ERR_INVALID_ARGUMENT,
            format!(
                "source file exceeds the maximum multipart size of {MAX_SOURCE_FILE_MULTIPART_BYTES} bytes"
            ),
        ));
    }
    let actual_sha = input
        .sha256
        .unwrap_or_else(|| sha256_file_sync(&input.path));
    let blob_dir = source_files_blob_dir(store_dir);
    tokio::fs::create_dir_all(&blob_dir).await.map_err(|err| {
        AppError::new(
            ERR_INTERNAL_ERROR,
            format!("failed to create source file blob store: {err}"),
        )
    })?;
    let blob_name = format!("{file_id}.blob");
    let blob_path = blob_dir.join(&blob_name);
    let (content_encoding, encrypted, encryption_key_id) = if repo_encryption.is_enabled() {
        let key = repo_encryption.require_key().map_err(|err| {
            AppError::new(
                ERR_INVALID_ARGUMENT,
                format!("repo encryption key is required to store source file blob: {err}"),
            )
        })?;
        write_encrypted_blob(
            repo_encryption,
            &key,
            &repo_encryption_domain_id(repo_root),
            &file_id,
            &input.path,
            &blob_path,
        )?;
        (
            SourceFileContentEncoding::RepoEncryptedBlob,
            true,
            Some(key.key_id),
        )
    } else {
        tokio::fs::copy(&input.path, &blob_path)
            .await
            .map_err(|err| {
                AppError::new(
                    ERR_INTERNAL_ERROR,
                    format!("failed to store source file blob: {err}"),
                )
            })?;
        (SourceFileContentEncoding::Blob, false, None)
    };
    let record = SourceFileRecord {
        file_id,
        original_name,
        mime_type,
        size_bytes: input.size_bytes,
        sha256: actual_sha,
        source_path,
        metadata_json: input.metadata_json,
        stored_at_ms: Utc::now().timestamp_millis(),
        encrypted,
        encryption_key_id,
        content_encoding,
        content: blob_name,
    };
    write_source_file_record(store_dir, &record).await?;
    Ok(StoredSourceFileRecord {
        item: record.to_item(),
        record,
    })
}

async fn multipart_next_field(multipart: &mut Multipart) -> Result<Option<Field<'_>>, AppError> {
    multipart.next_field().await.map_err(|err| {
        AppError::new(
            ERR_INVALID_ARGUMENT,
            format!("multipart source-file upload is invalid: {err}"),
        )
    })
}

async fn read_multipart_text(field: Field<'_>) -> Result<String, AppError> {
    field.text().await.map_err(|err| {
        AppError::new(
            ERR_INVALID_ARGUMENT,
            format!("multipart source-file field is invalid: {err}"),
        )
    })
}

async fn save_multipart_source_file_field(
    store_dir: &FsPath,
    mut field: Field<'_>,
) -> Result<MultipartSourceFile, AppError> {
    let temp_dir = source_files_temp_dir(store_dir);
    tokio::fs::create_dir_all(&temp_dir).await.map_err(|err| {
        AppError::new(
            ERR_INTERNAL_ERROR,
            format!("failed to create source file temp store: {err}"),
        )
    })?;
    let original_name = field.file_name().map(str::to_string);
    let mime_type = field.content_type().map(str::to_string);
    let path = temp_dir.join(format!("{}.upload", Uuid::new_v4()));
    let mut file = StdFile::create(&path).map_err(|err| {
        AppError::new(
            ERR_INTERNAL_ERROR,
            format!("failed to create source file temp upload: {err}"),
        )
    })?;
    let mut hasher = Sha256::new();
    let mut size_bytes: u64 = 0;
    while let Some(chunk) = field.chunk().await.map_err(|err| {
        AppError::new(
            ERR_INVALID_ARGUMENT,
            format!("multipart source-file chunk is invalid: {err}"),
        )
    })? {
        size_bytes = size_bytes.saturating_add(chunk.len() as u64);
        if size_bytes > MAX_SOURCE_FILE_MULTIPART_BYTES as u64 {
            let _ = tokio::fs::remove_file(&path).await;
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                format!(
                    "source file exceeds the maximum multipart size of {MAX_SOURCE_FILE_MULTIPART_BYTES} bytes"
                ),
            ));
        }
        hasher.update(&chunk);
        file.write_all(&chunk).map_err(|err| {
            AppError::new(
                ERR_INTERNAL_ERROR,
                format!("failed to write source file temp upload: {err}"),
            )
        })?;
    }
    file.flush().map_err(|err| {
        AppError::new(
            ERR_INTERNAL_ERROR,
            format!("failed to flush source file temp upload: {err}"),
        )
    })?;
    Ok(MultipartSourceFile {
        path,
        original_name,
        mime_type,
        size_bytes,
        sha256: format!("{:x}", hasher.finalize()),
    })
}

fn parse_multipart_metadata(raw: &str) -> Result<AdminSourceFileMultipartMetadata, AppError> {
    serde_json::from_str(raw.trim()).map_err(|err| {
        AppError::new(
            ERR_INVALID_ARGUMENT,
            format!("metadata must be valid JSON: {err}"),
        )
    })
}

fn parse_multipart_json_value(raw: &str) -> Result<Value, AppError> {
    serde_json::from_str(raw.trim()).map_err(|err| {
        AppError::new(
            ERR_INVALID_ARGUMENT,
            format!("metadata_json must be valid JSON: {err}"),
        )
    })
}

fn parse_bool_field(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

async fn remove_files_best_effort(paths: &[PathBuf]) {
    for path in paths {
        let _ = tokio::fs::remove_file(path).await;
    }
}

async fn write_source_file_record(
    store_dir: &FsPath,
    record: &SourceFileRecord,
) -> Result<(), AppError> {
    tokio::fs::create_dir_all(store_dir).await.map_err(|err| {
        AppError::new(
            ERR_INTERNAL_ERROR,
            format!("failed to create source file store: {err}"),
        )
    })?;
    let record_path = source_file_record_path(store_dir, &record.file_id)?;
    let payload = serde_json::to_vec_pretty(record).map_err(|err| {
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
        })
}

fn sha256_file_sync(path: &FsPath) -> String {
    let mut hasher = Sha256::new();
    if let Ok(mut file) = StdFile::open(path) {
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => hasher.update(&buffer[..read]),
                Err(_) => break,
            }
        }
    }
    format!("{:x}", hasher.finalize())
}

fn write_encrypted_blob(
    repo_encryption: &RepoEncryptionConfig,
    key: &crate::repo_encryption::ResolvedRepoEncryptionKey,
    domain_id: &str,
    file_id: &str,
    source_path: &FsPath,
    blob_path: &FsPath,
) -> Result<(), AppError> {
    let mut reader = StdFile::open(source_path).map_err(|err| {
        AppError::new(
            ERR_INTERNAL_ERROR,
            format!("failed to open source file for blob encryption: {err}"),
        )
    })?;
    let mut writer = StdFile::create(blob_path).map_err(|err| {
        AppError::new(
            ERR_INTERNAL_ERROR,
            format!("failed to create encrypted source file blob: {err}"),
        )
    })?;
    writer
        .write_all(SOURCE_FILE_ENCRYPTED_BLOB_MAGIC)
        .map_err(|err| {
            AppError::new(
                ERR_INTERNAL_ERROR,
                format!("failed to write encrypted source file blob header: {err}"),
            )
        })?;
    let header = serde_json::to_vec(&EncryptedBlobHeader {
        version: 1,
        key_id: key.key_id.clone(),
        chunk_size: SOURCE_FILE_BLOB_CHUNK_BYTES,
    })
    .map_err(|err| {
        AppError::new(
            ERR_INTERNAL_ERROR,
            format!("failed to serialize encrypted source file blob header: {err}"),
        )
    })?;
    writer.write_all(&header).map_err(|err| {
        AppError::new(
            ERR_INTERNAL_ERROR,
            format!("failed to write encrypted source file blob header: {err}"),
        )
    })?;
    writer.write_all(b"\n").map_err(|err| {
        AppError::new(
            ERR_INTERNAL_ERROR,
            format!("failed to write encrypted source file blob header: {err}"),
        )
    })?;
    let mut chunk_index = 0_u64;
    let mut buffer = vec![0_u8; SOURCE_FILE_BLOB_CHUNK_BYTES];
    loop {
        let read = reader.read(&mut buffer).map_err(|err| {
            AppError::new(
                ERR_INTERNAL_ERROR,
                format!("failed to read source file for blob encryption: {err}"),
            )
        })?;
        if read == 0 {
            break;
        }
        let (nonce, ciphertext) = repo_encryption
            .protect_bytes_chunk(
                key,
                domain_id,
                file_id,
                SOURCE_FILE_BLOB_PURPOSE,
                chunk_index,
                &buffer[..read],
            )
            .map_err(|err| {
                AppError::new(
                    ERR_INTERNAL_ERROR,
                    format!("failed to encrypt source file blob: {err}"),
                )
            })?;
        writer
            .write_all(&(read as u64).to_be_bytes())
            .map_err(|err| {
                AppError::new(
                    ERR_INTERNAL_ERROR,
                    format!("failed to write encrypted source file blob chunk: {err}"),
                )
            })?;
        writer
            .write_all(&(nonce.len() as u32).to_be_bytes())
            .map_err(|err| {
                AppError::new(
                    ERR_INTERNAL_ERROR,
                    format!("failed to write encrypted source file blob chunk: {err}"),
                )
            })?;
        writer
            .write_all(&(ciphertext.len() as u64).to_be_bytes())
            .map_err(|err| {
                AppError::new(
                    ERR_INTERNAL_ERROR,
                    format!("failed to write encrypted source file blob chunk: {err}"),
                )
            })?;
        writer.write_all(&nonce).map_err(|err| {
            AppError::new(
                ERR_INTERNAL_ERROR,
                format!("failed to write encrypted source file blob chunk: {err}"),
            )
        })?;
        writer.write_all(&ciphertext).map_err(|err| {
            AppError::new(
                ERR_INTERNAL_ERROR,
                format!("failed to write encrypted source file blob chunk: {err}"),
            )
        })?;
        chunk_index = chunk_index.saturating_add(1);
    }
    writer.flush().map_err(|err| {
        AppError::new(
            ERR_INTERNAL_ERROR,
            format!("failed to flush encrypted source file blob: {err}"),
        )
    })
}

fn read_blob_file(path: &FsPath) -> Result<Vec<u8>, AppError> {
    std::fs::read(path).map_err(|err| {
        AppError::new(
            ERR_INTERNAL_ERROR,
            format!("failed to read source file blob: {err}"),
        )
    })
}

fn read_encrypted_blob(
    repo_encryption: &RepoEncryptionConfig,
    key: &crate::repo_encryption::ResolvedRepoEncryptionKey,
    domain_id: &str,
    file_id: &str,
    path: &FsPath,
) -> Result<Vec<u8>, AppError> {
    let file = StdFile::open(path).map_err(|err| {
        AppError::new(
            ERR_INTERNAL_ERROR,
            format!("failed to open encrypted source file blob: {err}"),
        )
    })?;
    let mut reader = BufReader::new(file);
    let mut magic = vec![0_u8; SOURCE_FILE_ENCRYPTED_BLOB_MAGIC.len()];
    reader.read_exact(&mut magic).map_err(|err| {
        AppError::new(
            ERR_INVALID_ARGUMENT,
            format!("stored encrypted source file blob is invalid: {err}"),
        )
    })?;
    if magic != SOURCE_FILE_ENCRYPTED_BLOB_MAGIC {
        return Err(AppError::new(
            ERR_INVALID_ARGUMENT,
            "stored encrypted source file blob has an invalid header",
        ));
    }
    let mut header_line = Vec::new();
    reader.read_until(b'\n', &mut header_line).map_err(|err| {
        AppError::new(
            ERR_INVALID_ARGUMENT,
            format!("stored encrypted source file blob header is invalid: {err}"),
        )
    })?;
    let header: EncryptedBlobHeader =
        serde_json::from_slice(header_line.trim_ascii()).map_err(|err| {
            AppError::new(
                ERR_INVALID_ARGUMENT,
                format!("stored encrypted source file blob header is invalid: {err}"),
            )
        })?;
    if header.key_id != key.key_id {
        return Err(AppError::new(
            ERR_INVALID_ARGUMENT,
            "repository encryption key material cannot decrypt this source file blob",
        ));
    }
    let mut plaintext = Vec::new();
    let mut chunk_index = 0_u64;
    loop {
        let mut plain_len_bytes = [0_u8; 8];
        match reader.read_exact(&mut plain_len_bytes) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(err) => {
                return Err(AppError::new(
                    ERR_INVALID_ARGUMENT,
                    format!("stored encrypted source file blob chunk is invalid: {err}"),
                ))
            }
        }
        let mut nonce_len_bytes = [0_u8; 4];
        let mut cipher_len_bytes = [0_u8; 8];
        reader.read_exact(&mut nonce_len_bytes).map_err(|err| {
            AppError::new(
                ERR_INVALID_ARGUMENT,
                format!("stored encrypted source file blob chunk is invalid: {err}"),
            )
        })?;
        reader.read_exact(&mut cipher_len_bytes).map_err(|err| {
            AppError::new(
                ERR_INVALID_ARGUMENT,
                format!("stored encrypted source file blob chunk is invalid: {err}"),
            )
        })?;
        let plain_len = u64::from_be_bytes(plain_len_bytes) as usize;
        let nonce_len = u32::from_be_bytes(nonce_len_bytes) as usize;
        let cipher_len = u64::from_be_bytes(cipher_len_bytes) as usize;
        let mut nonce = vec![0_u8; nonce_len];
        let mut ciphertext = vec![0_u8; cipher_len];
        reader.read_exact(&mut nonce).map_err(|err| {
            AppError::new(
                ERR_INVALID_ARGUMENT,
                format!("stored encrypted source file blob chunk is invalid: {err}"),
            )
        })?;
        reader.read_exact(&mut ciphertext).map_err(|err| {
            AppError::new(
                ERR_INVALID_ARGUMENT,
                format!("stored encrypted source file blob chunk is invalid: {err}"),
            )
        })?;
        let chunk = repo_encryption
            .unprotect_bytes_chunk(
                key,
                domain_id,
                file_id,
                SOURCE_FILE_BLOB_PURPOSE,
                chunk_index,
                &nonce,
                &ciphertext,
            )
            .map_err(|err| {
                AppError::new(
                    ERR_INVALID_ARGUMENT,
                    format!("failed to decrypt source file blob: {err}"),
                )
            })?;
        if chunk.len() != plain_len {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "stored encrypted source file blob chunk length does not match header",
            ));
        }
        plaintext.extend_from_slice(&chunk);
        chunk_index = chunk_index.saturating_add(1);
    }
    Ok(plaintext)
}

async fn extract_zip_archive_source_files(
    store_dir: &FsPath,
    repo_root: &FsPath,
    repo_encryption: &RepoEncryptionConfig,
    archive_path: &FsPath,
    parent: &SourceFileRecord,
    cleanup_paths: &mut Vec<PathBuf>,
) -> Result<Vec<AdminSourceFileItem>, AppError> {
    let archive_path = archive_path.to_path_buf();
    let store_dir = store_dir.to_path_buf();
    let repo_root = repo_root.to_path_buf();
    let parent = parent.clone();
    let extraction_store_dir = store_dir.clone();
    let extracted_inputs = tokio::task::spawn_blocking(move || {
        extract_zip_archive_to_temp(&extraction_store_dir, &archive_path, &parent)
    })
    .await
    .map_err(|err| {
        AppError::new(
            ERR_INTERNAL_ERROR,
            format!("zip archive extraction task failed: {err}"),
        )
    })??;
    let mut items = Vec::with_capacity(extracted_inputs.len());
    for input in extracted_inputs {
        cleanup_paths.push(input.path.clone());
        let stored =
            store_source_file_from_path(&store_dir, &repo_root, repo_encryption, input).await?;
        items.push(stored.item);
    }
    Ok(items)
}

fn extract_zip_archive_to_temp(
    store_dir: &FsPath,
    archive_path: &FsPath,
    parent: &SourceFileRecord,
) -> Result<Vec<SourceFilePathInput>, AppError> {
    let archive_file = StdFile::open(archive_path).map_err(|err| {
        AppError::new(
            ERR_INVALID_ARGUMENT,
            format!("failed to open zip archive for extraction: {err}"),
        )
    })?;
    let mut archive = ZipArchive::new(archive_file).map_err(|err| {
        AppError::new(
            ERR_INVALID_ARGUMENT,
            format!("compressed source file is not a readable zip archive: {err}"),
        )
    })?;
    if archive.len() > MAX_SOURCE_ARCHIVE_ENTRIES {
        return Err(AppError::new(
            ERR_INVALID_ARGUMENT,
            format!("zip archive exceeds the maximum entry count of {MAX_SOURCE_ARCHIVE_ENTRIES}"),
        ));
    }
    let temp_dir = source_files_temp_dir(store_dir);
    std::fs::create_dir_all(&temp_dir).map_err(|err| {
        AppError::new(
            ERR_INTERNAL_ERROR,
            format!("failed to create source file archive temp store: {err}"),
        )
    })?;
    let mut total_uncompressed = 0_u64;
    let mut inputs = Vec::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|err| {
            AppError::new(
                ERR_INVALID_ARGUMENT,
                format!("failed to read zip archive entry: {err}"),
            )
        })?;
        if entry.is_dir() {
            continue;
        }
        let entry_path = match safe_archive_entry_path(&entry) {
            Ok(path) => path,
            Err(_) => continue,
        };
        let entry_size = entry.size();
        total_uncompressed = total_uncompressed.saturating_add(entry_size);
        if total_uncompressed > MAX_SOURCE_ARCHIVE_TOTAL_UNCOMPRESSED_BYTES {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                format!(
                    "zip archive exceeds the maximum total extracted size of {MAX_SOURCE_ARCHIVE_TOTAL_UNCOMPRESSED_BYTES} bytes"
                ),
            ));
        }
        if entry_size > MAX_SOURCE_FILE_MULTIPART_BYTES as u64 {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                format!(
                    "zip archive entry exceeds the maximum source file size of {MAX_SOURCE_FILE_MULTIPART_BYTES} bytes"
                ),
            ));
        }
        let temp_path = temp_dir.join(format!("{}.extract", Uuid::new_v4()));
        let (size_bytes, sha256) = copy_zip_entry_to_temp(&mut entry, &temp_path)?;
        let source_path = extracted_source_path(parent, &entry_path)?;
        let metadata_json = merge_archive_metadata(
            parent.metadata_json.clone(),
            &parent.file_id,
            &parent.original_name,
            &entry_path,
            index,
            entry.compressed_size(),
        );
        inputs.push(SourceFilePathInput {
            file_id: None,
            original_name: entry_path
                .rsplit('/')
                .next()
                .filter(|value| !value.is_empty())
                .unwrap_or("archive-entry")
                .to_string(),
            mime_type: Some(mime_type_from_path(&entry_path).to_string()),
            path: temp_path,
            size_bytes,
            sha256: Some(sha256),
            source_path: Some(source_path),
            metadata_json: Some(metadata_json),
        });
    }
    Ok(inputs)
}

fn copy_zip_entry_to_temp(
    entry: &mut ZipFile<'_>,
    temp_path: &FsPath,
) -> Result<(u64, String), AppError> {
    let mut output = StdFile::create(temp_path).map_err(|err| {
        AppError::new(
            ERR_INTERNAL_ERROR,
            format!("failed to create extracted zip entry temp file: {err}"),
        )
    })?;
    let mut hasher = Sha256::new();
    let mut size_bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = entry.read(&mut buffer).map_err(|err| {
            AppError::new(
                ERR_INVALID_ARGUMENT,
                format!("failed to read zip archive entry content: {err}"),
            )
        })?;
        if read == 0 {
            break;
        }
        size_bytes = size_bytes.saturating_add(read as u64);
        if size_bytes > MAX_SOURCE_FILE_MULTIPART_BYTES as u64 {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                format!(
                    "zip archive entry exceeds the maximum source file size of {MAX_SOURCE_FILE_MULTIPART_BYTES} bytes"
                ),
            ));
        }
        hasher.update(&buffer[..read]);
        output.write_all(&buffer[..read]).map_err(|err| {
            AppError::new(
                ERR_INTERNAL_ERROR,
                format!("failed to write extracted zip entry temp file: {err}"),
            )
        })?;
    }
    output.flush().map_err(|err| {
        AppError::new(
            ERR_INTERNAL_ERROR,
            format!("failed to flush extracted zip entry temp file: {err}"),
        )
    })?;
    Ok((size_bytes, format!("{:x}", hasher.finalize())))
}

fn safe_archive_entry_path(entry: &ZipFile<'_>) -> Result<String, AppError> {
    let Some(path) = entry.enclosed_name() else {
        return Err(AppError::new(
            ERR_INVALID_ARGUMENT,
            "zip archive entry path is unsafe",
        ));
    };
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => {
                let part = value.to_string_lossy();
                let sanitized = sanitize_archive_path_part(&part);
                if !sanitized.is_empty() {
                    parts.push(sanitized);
                }
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(AppError::new(
                    ERR_INVALID_ARGUMENT,
                    "zip archive entry path is unsafe",
                ))
            }
        }
    }
    if parts.is_empty() {
        return Err(AppError::new(
            ERR_INVALID_ARGUMENT,
            "zip archive entry path is empty",
        ));
    }
    Ok(parts.join("/"))
}

fn sanitize_archive_path_part(raw: &str) -> String {
    raw.chars()
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
        .chars()
        .take(191)
        .collect()
}

fn extracted_source_path(parent: &SourceFileRecord, entry_path: &str) -> Result<String, AppError> {
    let base = parent
        .source_path
        .as_deref()
        .map(strip_zip_extension)
        .unwrap_or_else(|| strip_zip_extension(&parent.original_name));
    safe_source_path(&format!("{base}/{entry_path}"))
}

fn strip_zip_extension(path: &str) -> String {
    path.strip_suffix(".zip").unwrap_or(path).to_string()
}

fn merge_archive_metadata(
    parent_metadata: Option<Value>,
    parent_file_id: &str,
    parent_original_name: &str,
    entry_path: &str,
    entry_index: usize,
    compressed_size_bytes: u64,
) -> Value {
    let mut object = match parent_metadata {
        Some(Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    };
    object.insert(
        "archive".to_string(),
        serde_json::json!({
            "parentFileId": parent_file_id,
            "parentOriginalName": parent_original_name,
            "entryPath": entry_path,
            "entryIndex": entry_index,
            "compressedSizeBytes": compressed_size_bytes
        }),
    );
    Value::Object(object)
}

fn is_zip_archive(original_name: &str, mime_type: &str) -> bool {
    original_name.to_ascii_lowercase().ends_with(".zip")
        || matches!(
            mime_type.trim().to_ascii_lowercase().as_str(),
            "application/zip"
                | "application/x-zip"
                | "application/x-zip-compressed"
                | "multipart/x-zip"
                | "application/octet-stream+zip"
        )
}

fn mime_type_from_path(path: &str) -> &'static str {
    match FsPath::new(path)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "txt" | "log" => "text/plain",
        "md" | "markdown" => "text/markdown",
        "csv" => "text/csv",
        "json" => "application/json",
        "pdf" => "application/pdf",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
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
    let bytes = match record.content_encoding {
        SourceFileContentEncoding::Base64 => {
            Base64Engine.decode(record.content.trim()).map_err(|err| {
                AppError::new(
                    ERR_INVALID_ARGUMENT,
                    format!("stored source file content is invalid: {err}"),
                )
            })?
        }
        SourceFileContentEncoding::RepoEncryptedBase64 => {
            let key = repo_encryption.require_key().map_err(|err| {
                AppError::new(
                    ERR_INVALID_ARGUMENT,
                    format!("repo encryption key is required to read source file: {err}"),
                )
            })?;
            let domain_id = repo_encryption_domain_id(repo_root);
            let encoded = repo_encryption
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
                })?;
            Base64Engine.decode(encoded.trim()).map_err(|err| {
                AppError::new(
                    ERR_INVALID_ARGUMENT,
                    format!("stored source file content is invalid: {err}"),
                )
            })?
        }
        SourceFileContentEncoding::Blob => {
            let blob_path = source_file_blob_path(store_dir, &record.content)?;
            read_blob_file(&blob_path)?
        }
        SourceFileContentEncoding::RepoEncryptedBlob => {
            let key = repo_encryption.require_key().map_err(|err| {
                AppError::new(
                    ERR_INVALID_ARGUMENT,
                    format!("repo encryption key is required to read source file blob: {err}"),
                )
            })?;
            let blob_path = source_file_blob_path(store_dir, &record.content)?;
            read_encrypted_blob(
                repo_encryption,
                &key,
                &repo_encryption_domain_id(repo_root),
                &record.file_id,
                &blob_path,
            )?
        }
    };
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

fn source_file_blob_path(store_dir: &FsPath, blob_name: &str) -> Result<PathBuf, AppError> {
    Ok(source_files_blob_dir(store_dir).join(safe_source_blob_name(blob_name)?))
}

fn safe_source_blob_name(raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('.')
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || !trimmed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(AppError::new(
            ERR_INVALID_ARGUMENT,
            "source file blob name contains invalid characters",
        ));
    }
    Ok(trimmed.to_string())
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

    #[tokio::test]
    async fn source_file_multipart_blob_extracts_zip_entries_under_archive_path() {
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
        let archive_path = temp.path().join("company.zip");
        {
            let archive_file = StdFile::create(&archive_path).expect("archive");
            let mut zip = zip::ZipWriter::new(archive_file);
            let options = zip::write::FileOptions::default();
            zip.start_file("notes/strategy.txt", options)
                .expect("start file");
            zip.write_all(b"archive strategy notes")
                .expect("write file");
            zip.finish().expect("finish zip");
        }
        let archive_sha = sha256_file_sync(&archive_path);
        let stored = store_source_file_from_path(
            &store_dir,
            &repo_root,
            &RepoEncryptionConfig::default(),
            SourceFilePathInput {
                file_id: Some("archive-1".to_string()),
                original_name: "company.zip".to_string(),
                mime_type: Some("application/zip".to_string()),
                path: archive_path.clone(),
                size_bytes: std::fs::metadata(&archive_path).expect("metadata").len(),
                sha256: Some(archive_sha),
                source_path: Some("okacam/business-analytics/wodo/doc-1/company.zip".to_string()),
                metadata_json: Some(serde_json::json!({ "tenant": "wodo" })),
            },
        )
        .await
        .expect("store archive");
        let mut cleanup_paths = Vec::new();
        let extracted = extract_zip_archive_source_files(
            &store_dir,
            &repo_root,
            &RepoEncryptionConfig::default(),
            &archive_path,
            &stored.record,
            &mut cleanup_paths,
        )
        .await
        .expect("extract archive");

        assert_eq!(extracted.len(), 1);
        assert_eq!(
            extracted[0].source_path.as_deref(),
            Some("okacam/business-analytics/wodo/doc-1/company/notes/strategy.txt")
        );
        let content = load_source_file_content(
            &store_dir,
            &repo_root,
            &RepoEncryptionConfig::default(),
            &extracted[0].file_id,
        )
        .await
        .expect("content");
        assert_eq!(content.bytes, b"archive strategy notes");
        remove_files_best_effort(&cleanup_paths).await;
    }

    #[tokio::test]
    async fn source_file_blob_round_trips_encrypted_content_without_plaintext_blob() {
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
        let input_path = temp.path().join("private.txt");
        std::fs::write(&input_path, b"private blob plan").expect("input file");
        let mut repo_encryption = RepoEncryptionConfig {
            encryption_mode: RepoEncryptionMode::ApplicationManagedEncryption,
            ..RepoEncryptionConfig::default()
        };
        repo_encryption.apply_defaults();
        let stored = store_source_file_from_path(
            &store_dir,
            &repo_root,
            &repo_encryption,
            SourceFilePathInput {
                file_id: Some("blob-1".to_string()),
                original_name: "private.txt".to_string(),
                mime_type: Some("text/plain".to_string()),
                path: input_path,
                size_bytes: "private blob plan".len() as u64,
                sha256: None,
                source_path: Some("okacam/business-analytics/private.txt".to_string()),
                metadata_json: None,
            },
        )
        .await
        .expect("store blob");

        assert!(stored.item.encrypted);
        let blob_path =
            source_file_blob_path(&store_dir, &stored.record.content).expect("blob path");
        let raw_blob = std::fs::read(blob_path).expect("blob");
        let raw_blob = String::from_utf8_lossy(&raw_blob);
        assert!(!raw_blob.contains("private blob plan"));
        let content = load_source_file_content(&store_dir, &repo_root, &repo_encryption, "blob-1")
            .await
            .expect("content");
        assert_eq!(content.bytes, b"private blob plan");
        std::env::remove_var(DEFAULT_REPO_ENCRYPTION_KEY_ENV);
    }
}
