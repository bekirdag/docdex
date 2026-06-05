use axum::{
    extract::{Path as AxumPath, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::Value;

use crate::error::{ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT, ERR_MEMORY_DISABLED};
use crate::http_api::json_error;
use crate::personal_preferences::{
    status_payload_with_config, PersonalPreferenceAiTerminalCaptureRequest,
    PersonalPreferenceGeneratedSkillActionRequest, PersonalPreferenceGeneratedSkillsSyncOptions,
    PersonalPreferenceOperatorEventRequest, PersonalPreferencesClaimsQuery,
    PersonalPreferencesCloneOptions,
};
use crate::search::AppState;

#[derive(Debug, Deserialize)]
pub(crate) struct PersonalPreferencesCaptureListQuery {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PersonalPreferencesSearchQuery {
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    include_sensitive: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PersonalPreferencesClaimsQueryParams {
    #[serde(default, alias = "q")]
    query: Option<String>,
    #[serde(default)]
    truth_status: Option<String>,
    #[serde(default)]
    claim_origin: Option<String>,
    #[serde(default)]
    include_sensitive: Option<bool>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PersonalPreferencesReviewQueueQuery {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PersonalPreferencesReviewLogQuery {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PersonalPreferencesProcessRequest {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    retry_failed: bool,
    #[serde(default)]
    retry_stale_processing_ms: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PersonalPreferencesScanRequest {
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PersonalPreferencesExportRequest {
    #[serde(default)]
    capture_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PersonalPreferencesPurgeRequest {
    #[serde(default)]
    include_exports: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PersonalPreferencesReviewRequest {
    verdict: String,
    #[serde(default)]
    notes: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PersonalPreferencesClaimOverrideRequest {
    value: String,
    #[serde(default)]
    notes: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PersonalPreferencesClaimForgetRequest {
    #[serde(default)]
    notes: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PersonalPreferencesFeedbackRequest {
    event_type: String,
    #[serde(default)]
    claim_id: Option<String>,
    #[serde(default)]
    capture_id: Option<String>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    attribute: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    metadata: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PersonalPreferencesOperatorEventsQuery {
    #[serde(default, alias = "kind", alias = "event_type")]
    event_kind: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    repo_root: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PersonalPreferencesOperatorEventScanRequest {
    #[serde(default)]
    repo_root: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PersonalPreferencesSnapshotsQuery {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PersonalPreferencesRoutinesQuery {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PersonalPreferencesMindMapQuery {
    #[serde(default, alias = "q")]
    query: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    include_sensitive: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PersonalPreferencesPlaybooksQuery {
    #[serde(default)]
    min_confidence: Option<f32>,
    #[serde(default)]
    min_support_count: Option<usize>,
    #[serde(default)]
    include_sensitive: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AiTerminalIntegrationsBootstrapRequest {
    #[serde(default)]
    terminals: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AiTerminalEventsQuery {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GeneratedSkillEventsQuery {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PersonalPreferencesCloneRequest {
    query: String,
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    allow_sensitive: Option<bool>,
    #[serde(default)]
    current_repo_root: Option<String>,
    #[serde(default)]
    max_records: Option<usize>,
    #[serde(default)]
    budget_tokens: Option<usize>,
    #[serde(default)]
    task_type: Option<String>,
    #[serde(default)]
    risk_level: Option<String>,
    #[serde(default)]
    current_files: Vec<String>,
    #[serde(default)]
    current_plan_path: Option<String>,
    #[serde(default)]
    enforcement_level: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PersonalPreferencesCloneReplayRequest {
    query: String,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    allow_sensitive: Option<bool>,
    #[serde(default)]
    current_repo_root: Option<String>,
    #[serde(default)]
    max_records: Option<usize>,
    #[serde(default)]
    budget_tokens: Option<usize>,
    #[serde(default)]
    expected_categories: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PersonalPreferencesCloneReplayDatasetRequest {
    #[serde(default)]
    ci_subset: Option<bool>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    current_repo_root: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PersonalPreferencesCloneReplaySuiteRequest {
    #[serde(default)]
    ci_subset: Option<bool>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    threshold: Option<f32>,
    #[serde(default)]
    allow_sensitive: Option<bool>,
    #[serde(default)]
    current_repo_root: Option<String>,
    #[serde(default)]
    max_records: Option<usize>,
    #[serde(default)]
    budget_tokens: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PersonalPreferencesPruneRequest {
    #[serde(default)]
    raw_retention_days: Option<u32>,
    #[serde(default)]
    derived_retention_days: Option<u32>,
    #[serde(default)]
    apply: Option<bool>,
}

fn personal_preferences_disabled_message() -> &'static str {
    "personal preferences memory is disabled; enable [personal_preferences].enabled"
}

fn personal_preferences_digest_disabled_message() -> &'static str {
    "personal preferences digest is disabled; enable [personal_preferences].digest_enabled"
}

pub(crate) async fn personal_preferences_status_handler(State(state): State<AppState>) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences.store.status() {
        Ok(status) => match status_payload_with_config(status, &personal_preferences.config) {
            Ok(payload) => Json(payload).into_response(),
            Err(err) => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                err.to_string(),
            ),
        },
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_categories_handler(
    State(state): State<AppState>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences.store.list_categories() {
        Ok(categories) => Json(categories).into_response(),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_retention_policies_handler(
    State(state): State<AppState>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences.store.list_retention_policies() {
        Ok(policies) => Json(policies).into_response(),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_list_captures_handler(
    State(state): State<AppState>,
    Query(query): Query<PersonalPreferencesCaptureListQuery>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    let limit = query.limit.unwrap_or(20).clamp(1, 200);
    let offset = query.offset.unwrap_or(0);
    match personal_preferences
        .store
        .list_captures(query.status.as_deref(), limit, offset)
    {
        Ok(list) => Json(list).into_response(),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_read_capture_handler(
    State(state): State<AppState>,
    AxumPath(capture_id): AxumPath<String>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    let capture_id = capture_id.trim().to_string();
    if capture_id.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "capture_id must not be empty",
        );
    }
    match personal_preferences.store.read_capture(&capture_id) {
        Ok(Some(capture)) => Json(capture).into_response(),
        Ok(None) => json_error(
            StatusCode::NOT_FOUND,
            ERR_INVALID_ARGUMENT,
            "personal preferences capture not found",
        ),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_search_handler(
    State(state): State<AppState>,
    Query(query): Query<PersonalPreferencesSearchQuery>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    let q = query.q.unwrap_or_default();
    let limit = query.limit.unwrap_or(10).clamp(1, 100);
    let include_sensitive = query.include_sensitive.unwrap_or(true);
    match personal_preferences
        .store
        .search_records_with_policy(&q, limit, include_sensitive)
    {
        Ok(items) => {
            Json(crate::personal_preferences::PersonalPreferencesSearchResponse { query: q, items })
                .into_response()
        }
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_claims_handler(
    State(state): State<AppState>,
    Query(query): Query<PersonalPreferencesClaimsQueryParams>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    let request = PersonalPreferencesClaimsQuery {
        query: query
            .query
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        truth_status: query
            .truth_status
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        claim_origin: query
            .claim_origin
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        include_sensitive: query.include_sensitive.unwrap_or(false),
        limit: query.limit,
        offset: query.offset,
    };
    match personal_preferences.store.list_claims(request) {
        Ok(list) => Json(list).into_response(),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_claim_read_handler(
    State(state): State<AppState>,
    AxumPath(claim_id): AxumPath<String>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    let claim_id = claim_id.trim().to_string();
    if claim_id.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "claim_id must not be empty",
        );
    }
    match personal_preferences.store.read_claim(&claim_id) {
        Ok(Some(claim)) => Json(claim).into_response(),
        Ok(None) => json_error(
            StatusCode::NOT_FOUND,
            ERR_INVALID_ARGUMENT,
            "personal preference claim not found",
        ),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_claim_review_handler(
    State(state): State<AppState>,
    AxumPath(claim_id): AxumPath<String>,
    Json(body): Json<PersonalPreferencesReviewRequest>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    let claim_id = claim_id.trim().to_string();
    if claim_id.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "claim_id must not be empty",
        );
    }
    match personal_preferences.store.review_claim(
        &claim_id,
        body.verdict.trim(),
        body.notes.as_deref(),
    ) {
        Ok(summary) => Json(summary).into_response(),
        Err(err) => json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_claim_override_handler(
    State(state): State<AppState>,
    AxumPath(claim_id): AxumPath<String>,
    Json(body): Json<PersonalPreferencesClaimOverrideRequest>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    let claim_id = claim_id.trim().to_string();
    if claim_id.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "claim_id must not be empty",
        );
    }
    let value = body.value.trim().to_string();
    if value.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "value must not be empty",
        );
    }
    match personal_preferences
        .store
        .override_claim(&claim_id, &value, body.notes.as_deref())
    {
        Ok(summary) => Json(summary).into_response(),
        Err(err) => json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_claim_forget_handler(
    State(state): State<AppState>,
    AxumPath(claim_id): AxumPath<String>,
    Json(body): Json<PersonalPreferencesClaimForgetRequest>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    let claim_id = claim_id.trim().to_string();
    if claim_id.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "claim_id must not be empty",
        );
    }
    match personal_preferences
        .store
        .forget_claim(&claim_id, body.notes.as_deref())
    {
        Ok(summary) => Json(summary).into_response(),
        Err(err) => json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_feedback_handler(
    State(state): State<AppState>,
    Json(body): Json<PersonalPreferencesFeedbackRequest>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    let event_type = body.event_type.trim().to_string();
    if event_type.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "event_type must not be empty",
        );
    }
    match personal_preferences.store.add_feedback_event(
        &event_type,
        body.claim_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty()),
        body.capture_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty()),
        body.category
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty()),
        body.attribute
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty()),
        body.value
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty()),
        body.notes.as_deref(),
        body.metadata.unwrap_or(Value::Null),
    ) {
        Ok(summary) => Json(summary).into_response(),
        Err(err) => json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_snapshots_handler(
    State(state): State<AppState>,
    Query(query): Query<PersonalPreferencesSnapshotsQuery>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences.store.list_snapshots(
        query.limit.unwrap_or(20).clamp(1, 200),
        query.offset.unwrap_or(0),
    ) {
        Ok(list) => Json(list).into_response(),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_snapshot_read_handler(
    State(state): State<AppState>,
    AxumPath(snapshot_id): AxumPath<String>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    let snapshot_id = snapshot_id.trim().to_string();
    if snapshot_id.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "snapshot_id must not be empty",
        );
    }
    match personal_preferences.store.read_snapshot(&snapshot_id) {
        Ok(Some(snapshot)) => Json(snapshot).into_response(),
        Ok(None) => json_error(
            StatusCode::NOT_FOUND,
            ERR_INVALID_ARGUMENT,
            "personal preference snapshot not found",
        ),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_snapshots_rebuild_handler(
    State(state): State<AppState>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences.store.rebuild_snapshots() {
        Ok(summary) => Json(summary).into_response(),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_operator_events_handler(
    State(state): State<AppState>,
    Query(query): Query<PersonalPreferencesOperatorEventsQuery>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences.store.list_operator_events(
        query.event_kind.as_deref(),
        query.action.as_deref(),
        query.repo_root.as_deref(),
        query.limit.unwrap_or(20).clamp(1, 200),
        query.offset.unwrap_or(0),
    ) {
        Ok(list) => Json(list).into_response(),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_operator_event_record_handler(
    State(state): State<AppState>,
    Json(payload): Json<PersonalPreferenceOperatorEventRequest>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences
        .store
        .record_operator_event(payload, "http")
    {
        Ok(event) => Json(event).into_response(),
        Err(err) => json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_operator_events_scan_artifacts_handler(
    State(state): State<AppState>,
    Json(payload): Json<PersonalPreferencesOperatorEventScanRequest>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    let repo_root = payload
        .repo_root
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| state.indexer.repo_root().to_path_buf());
    match personal_preferences
        .store
        .scan_operator_artifacts(&repo_root, payload.limit)
    {
        Ok(summary) => Json(summary).into_response(),
        Err(err) => json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_routines_handler(
    State(state): State<AppState>,
    Query(query): Query<PersonalPreferencesRoutinesQuery>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences.store.list_operator_routines(
        query.limit.unwrap_or(20).clamp(1, 200),
        query.offset.unwrap_or(0),
    ) {
        Ok(list) => Json(list).into_response(),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_routine_read_handler(
    State(state): State<AppState>,
    AxumPath(routine_id): AxumPath<String>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    let routine_id = routine_id.trim().to_string();
    if routine_id.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "routine_id must not be empty",
        );
    }
    match personal_preferences
        .store
        .read_operator_routine(&routine_id)
    {
        Ok(Some(routine)) => Json(routine).into_response(),
        Ok(None) => json_error(
            StatusCode::NOT_FOUND,
            ERR_INVALID_ARGUMENT,
            "personal preference operator routine not found",
        ),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_routine_explain_handler(
    State(state): State<AppState>,
    AxumPath(routine_id): AxumPath<String>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    let routine_id = routine_id.trim().to_string();
    if routine_id.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "routine_id must not be empty",
        );
    }
    match personal_preferences
        .store
        .explain_operator_routine(&routine_id)
    {
        Ok(Some(explanation)) => Json(explanation).into_response(),
        Ok(None) => json_error(
            StatusCode::NOT_FOUND,
            ERR_INVALID_ARGUMENT,
            "personal preference operator routine not found",
        ),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_routines_rebuild_handler(
    State(state): State<AppState>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences.store.rebuild_operator_routines() {
        Ok(summary) => Json(summary).into_response(),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_mind_map_handler(
    State(state): State<AppState>,
    Query(query): Query<PersonalPreferencesMindMapQuery>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    let query_text = query
        .query
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match personal_preferences.store.compile_mind_map(
        query_text,
        query.limit.unwrap_or(50).clamp(4, 200),
        query.include_sensitive.unwrap_or(false),
    ) {
        Ok(map) => Json(map).into_response(),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_playbooks_handler(
    State(state): State<AppState>,
    Query(query): Query<PersonalPreferencesPlaybooksQuery>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences.store.compile_operator_playbooks(
        query.min_confidence.unwrap_or(0.7),
        query.min_support_count.unwrap_or(2),
        query.include_sensitive.unwrap_or(false),
    ) {
        Ok(bundle) => Json(bundle).into_response(),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn ai_terminal_integrations_handler(State(state): State<AppState>) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences.store.list_ai_terminal_integrations() {
        Ok(summary) => Json(summary).into_response(),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn ai_terminal_status_handler(State(state): State<AppState>) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences.store.ai_terminal_status() {
        Ok(status) => Json(status).into_response(),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn ai_terminal_integrations_detect_handler(
    State(state): State<AppState>,
    Json(body): Json<AiTerminalIntegrationsBootstrapRequest>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences
        .store
        .detect_ai_terminal_integrations(body.terminals)
    {
        Ok(summary) => Json(summary).into_response(),
        Err(err) => json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            err.to_string(),
        ),
    }
}

pub(crate) async fn ai_terminal_events_handler(
    State(state): State<AppState>,
    Query(query): Query<AiTerminalEventsQuery>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences
        .store
        .list_ai_terminal_capture_events(query.limit.unwrap_or(50), query.offset.unwrap_or(0))
    {
        Ok(events) => Json(events).into_response(),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn ai_terminal_integrations_bootstrap_handler(
    State(state): State<AppState>,
    Json(body): Json<AiTerminalIntegrationsBootstrapRequest>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences
        .store
        .bootstrap_ai_terminal_integrations(body.terminals)
    {
        Ok(summary) => Json(summary).into_response(),
        Err(err) => json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            err.to_string(),
        ),
    }
}

pub(crate) async fn ai_terminal_capture_handler(
    State(state): State<AppState>,
    Json(body): Json<PersonalPreferenceAiTerminalCaptureRequest>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences.store.record_ai_terminal_capture(body) {
        Ok(event) => Json(event).into_response(),
        Err(err) => json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            err.to_string(),
        ),
    }
}

pub(crate) async fn ai_terminal_sync_skills_handler(
    State(state): State<AppState>,
    Json(body): Json<PersonalPreferenceGeneratedSkillsSyncOptions>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences.store.sync_generated_skills(body) {
        Ok(summary) => Json(summary).into_response(),
        Err(err) => json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_generated_skills_handler(
    State(state): State<AppState>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences.store.list_generated_skills() {
        Ok(list) => Json(list).into_response(),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_generated_skill_read_handler(
    State(state): State<AppState>,
    AxumPath(skill_id): AxumPath<String>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    let skill_id = skill_id.trim().to_string();
    if skill_id.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "skill_id must not be empty",
        );
    }
    match personal_preferences.store.read_generated_skill(&skill_id) {
        Ok(Some(skill)) => Json(skill).into_response(),
        Ok(None) => json_error(
            StatusCode::NOT_FOUND,
            ERR_INVALID_ARGUMENT,
            "personal preference generated skill not found",
        ),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_generated_skills_sync_handler(
    State(state): State<AppState>,
    Json(body): Json<PersonalPreferenceGeneratedSkillsSyncOptions>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences.store.sync_generated_skills(body) {
        Ok(summary) => Json(summary).into_response(),
        Err(err) => json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_generated_skills_preview_handler(
    State(state): State<AppState>,
    Json(body): Json<PersonalPreferenceGeneratedSkillsSyncOptions>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences.store.preview_generated_skills(body) {
        Ok(summary) => Json(summary).into_response(),
        Err(err) => json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_generated_skills_autopilot_handler(
    State(state): State<AppState>,
    Json(body): Json<PersonalPreferenceGeneratedSkillsSyncOptions>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences.store.sync_generated_skills(body) {
        Ok(mut summary) => {
            summary
                .notes
                .push("Autopilot one-shot processed generated skills through the registry, validation, and installer pipeline.".to_string());
            Json(summary).into_response()
        }
        Err(err) => json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_generated_skill_validate_handler(
    State(state): State<AppState>,
    AxumPath(skill_id): AxumPath<String>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences
        .store
        .validate_generated_skill(&skill_id)
    {
        Ok(summary) => Json(summary).into_response(),
        Err(err) => json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_generated_skill_install_handler(
    State(state): State<AppState>,
    AxumPath(skill_id): AxumPath<String>,
    Json(body): Json<PersonalPreferenceGeneratedSkillActionRequest>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    let skill_id = body.skill_id.unwrap_or(skill_id);
    match personal_preferences
        .store
        .install_generated_skill(&skill_id, body.terminals)
    {
        Ok(summary) => Json(summary).into_response(),
        Err(err) => json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_generated_skill_disable_handler(
    State(state): State<AppState>,
    AxumPath(skill_id): AxumPath<String>,
    Json(body): Json<PersonalPreferenceGeneratedSkillActionRequest>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    let skill_id = body.skill_id.unwrap_or(skill_id);
    match personal_preferences
        .store
        .disable_generated_skill(&skill_id, body.reason)
    {
        Ok(summary) => Json(summary).into_response(),
        Err(err) => json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_generated_skill_rollback_handler(
    State(state): State<AppState>,
    AxumPath(skill_id): AxumPath<String>,
    Json(body): Json<PersonalPreferenceGeneratedSkillActionRequest>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    let skill_id = body.skill_id.unwrap_or(skill_id);
    match personal_preferences
        .store
        .rollback_generated_skill(&skill_id, body.terminals)
    {
        Ok(summary) => Json(summary).into_response(),
        Err(err) => json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_generated_skill_events_handler(
    State(state): State<AppState>,
    Query(query): Query<GeneratedSkillEventsQuery>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences
        .store
        .list_generated_skill_events(query.limit.unwrap_or(50), query.offset.unwrap_or(0))
    {
        Ok(events) => Json(events).into_response(),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

fn clone_options_from_request(
    body: &PersonalPreferencesCloneRequest,
) -> (String, PersonalPreferencesCloneOptions) {
    (
        body.query.trim().to_string(),
        PersonalPreferencesCloneOptions {
            mode: body
                .mode
                .as_ref()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            allow_sensitive: body.allow_sensitive.unwrap_or(false),
            current_repo_root: body
                .current_repo_root
                .as_ref()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            max_records: body.max_records,
            budget_tokens: body.budget_tokens,
        },
    )
}

fn clone_options_from_replay_request(
    body: &PersonalPreferencesCloneReplayRequest,
) -> PersonalPreferencesCloneOptions {
    PersonalPreferencesCloneOptions {
        mode: body
            .mode
            .as_ref()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        allow_sensitive: body.allow_sensitive.unwrap_or(false),
        current_repo_root: body
            .current_repo_root
            .as_ref()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        max_records: body.max_records,
        budget_tokens: body.budget_tokens,
    }
}

fn clone_options_from_replay_suite_request(
    body: &PersonalPreferencesCloneReplaySuiteRequest,
) -> PersonalPreferencesCloneOptions {
    PersonalPreferencesCloneOptions {
        mode: None,
        allow_sensitive: body.allow_sensitive.unwrap_or(false),
        current_repo_root: normalize_optional_string(body.current_repo_root.as_deref()),
        max_records: body.max_records,
        budget_tokens: body.budget_tokens,
    }
}

fn normalize_optional_string(value: Option<&str>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) async fn personal_preferences_clone_context_handler(
    State(state): State<AppState>,
    Json(body): Json<PersonalPreferencesCloneRequest>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    let (query, options) = clone_options_from_request(&body);
    if query.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "query must not be empty",
        );
    }
    match personal_preferences
        .store
        .build_clone_context_pack(&query, options)
    {
        Ok(pack) => Json(pack).into_response(),
        Err(err) => json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_clone_directive_handler(
    State(state): State<AppState>,
    Json(body): Json<PersonalPreferencesCloneRequest>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    let (query, options) = clone_options_from_request(&body);
    if query.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "query must not be empty",
        );
    }
    match personal_preferences.store.build_clone_directive(
        &query,
        options,
        body.agent_id,
        body.task_type,
        body.risk_level,
        body.current_files,
        body.current_plan_path,
        body.enforcement_level,
    ) {
        Ok(directive) => Json(directive).into_response(),
        Err(err) => json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_clone_explain_handler(
    State(state): State<AppState>,
    Json(body): Json<PersonalPreferencesCloneRequest>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    let (query, options) = clone_options_from_request(&body);
    if query.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "query must not be empty",
        );
    }
    match personal_preferences
        .store
        .explain_clone_context(&query, options)
    {
        Ok(explanation) => Json(explanation).into_response(),
        Err(err) => json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_clone_evaluate_handler(
    State(state): State<AppState>,
    Json(body): Json<PersonalPreferencesCloneRequest>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    let (query, options) = clone_options_from_request(&body);
    if query.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "query must not be empty",
        );
    }
    match personal_preferences
        .store
        .evaluate_clone_context(&query, options)
    {
        Ok(evaluation) => Json(evaluation).into_response(),
        Err(err) => json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_clone_replay_evaluate_handler(
    State(state): State<AppState>,
    Json(body): Json<PersonalPreferencesCloneReplayRequest>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    let query = body.query.trim().to_string();
    if query.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "query must not be empty",
        );
    }
    let options = clone_options_from_replay_request(&body);
    match personal_preferences.store.evaluate_clone_replay(
        &query,
        options,
        body.expected_categories,
    ) {
        Ok(evaluation) => Json(evaluation).into_response(),
        Err(err) => json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_clone_replay_dataset_handler(
    State(state): State<AppState>,
    Json(body): Json<PersonalPreferencesCloneReplayDatasetRequest>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences.store.build_clone_replay_dataset(
        body.ci_subset.unwrap_or(false),
        body.limit,
        normalize_optional_string(body.current_repo_root.as_deref()),
    ) {
        Ok(dataset) => Json(dataset).into_response(),
        Err(err) => json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_clone_replay_suite_handler(
    State(state): State<AppState>,
    Json(body): Json<PersonalPreferencesCloneReplaySuiteRequest>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    let options = clone_options_from_replay_suite_request(&body);
    match personal_preferences.store.run_clone_replay_suite(
        body.ci_subset.unwrap_or(false),
        body.limit,
        body.threshold,
        options,
    ) {
        Ok(suite) => Json(suite).into_response(),
        Err(err) => json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_reviews_handler(
    State(state): State<AppState>,
    Query(query): Query<PersonalPreferencesReviewQueueQuery>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    let limit = query.limit.unwrap_or(20).clamp(1, 200);
    let offset = query.offset.unwrap_or(0);
    match personal_preferences
        .store
        .list_review_records(query.status.as_deref(), limit, offset)
    {
        Ok(list) => Json(list).into_response(),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_review_log_handler(
    State(state): State<AppState>,
    AxumPath(record_id): AxumPath<String>,
    Query(query): Query<PersonalPreferencesReviewLogQuery>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences.store.list_reviews_for_record(
        record_id.trim(),
        query.limit.unwrap_or(20).clamp(1, 200),
        query.offset.unwrap_or(0),
    ) {
        Ok(list) => Json(list).into_response(),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_review_handler(
    State(state): State<AppState>,
    AxumPath(record_id): AxumPath<String>,
    Json(payload): Json<PersonalPreferencesReviewRequest>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences.store.review_record(
        record_id.trim(),
        payload.verdict.trim(),
        payload.notes.as_deref(),
    ) {
        Ok(summary) => Json(summary).into_response(),
        Err(err) => json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_process_handler(
    State(state): State<AppState>,
    Json(payload): Json<PersonalPreferencesProcessRequest>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    if let Some(limit) = payload.limit {
        if limit == 0 {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                "limit must be > 0",
            );
        }
    }
    if let Some(stale_ms) = payload.retry_stale_processing_ms {
        if stale_ms < 0 {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                "retry_stale_processing_ms must be >= 0",
            );
        }
    }
    if !personal_preferences.config.digest_enabled {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_digest_disabled_message(),
        );
    }
    let requeued = match personal_preferences.store.requeue_captures_for_processing(
        payload.retry_failed,
        payload.retry_stale_processing_ms,
        payload.limit,
    ) {
        Ok(count) => count,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                err.to_string(),
            );
        }
    };
    match crate::personal_preferences::process_pending_with_local_agents(
        &personal_preferences.store,
        state.global_state_dir.as_deref(),
        &state.llm_config,
        &personal_preferences.config,
        payload.limit,
    )
    .await
    {
        Ok(mut summary) => {
            summary.requeued_captures = requeued;
            if let Some(profile_state) = state.profile_state.as_ref() {
                match crate::personal_preferences::project_safe_preferences_to_profile(
                    &personal_preferences.store,
                    &profile_state.manager,
                    profile_state.embedder.as_ref(),
                    &personal_preferences.config,
                    state.default_agent_id.as_deref(),
                )
                .await
                {
                    Ok(projected) => {
                        summary.projected_profile_preferences = projected;
                    }
                    Err(err) => {
                        return json_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            ERR_INTERNAL_ERROR,
                            err.to_string(),
                        );
                    }
                }
            }
            Json(summary).into_response()
        }
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_scan_handler(
    State(state): State<AppState>,
    Json(payload): Json<PersonalPreferencesScanRequest>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    let terminal_capture_enabled = if personal_preferences
        .config
        .capture_supported_client_transcripts
    {
        true
    } else {
        match personal_preferences
            .store
            .has_enabled_ai_terminal_capture_integrations()
        {
            Ok(enabled) => enabled,
            Err(err) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ERR_INTERNAL_ERROR,
                    err.to_string(),
                );
            }
        }
    };
    if !terminal_capture_enabled {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            "supported client transcript capture is disabled; enable [personal_preferences].capture_supported_client_transcripts or bootstrap an AI terminal integration",
        );
    }
    if let Some(limit) = payload.limit {
        if limit == 0 {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                "limit must be > 0",
            );
        }
    }
    match personal_preferences
        .store
        .scan_supported_client_transcripts(&personal_preferences.config, payload.limit)
    {
        Ok(summary) => Json(summary).into_response(),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_prune_handler(
    State(state): State<AppState>,
    Json(payload): Json<PersonalPreferencesPruneRequest>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    let raw_retention_days = payload
        .raw_retention_days
        .unwrap_or(personal_preferences.config.raw_retention_days);
    let derived_retention_days = payload
        .derived_retention_days
        .unwrap_or(personal_preferences.config.derived_retention_days);
    match personal_preferences.store.prune_retention(
        raw_retention_days,
        derived_retention_days,
        payload.apply.unwrap_or(false),
    ) {
        Ok(summary) => Json(summary).into_response(),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_export_handler(
    State(state): State<AppState>,
    Json(payload): Json<PersonalPreferencesExportRequest>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    if !personal_preferences.config.export_enabled {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            "personal preferences export is disabled; enable [personal_preferences].export_enabled",
        );
    }
    match personal_preferences
        .store
        .export_bundle(payload.capture_id.as_deref())
    {
        Ok(summary) => Json(summary).into_response(),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_redact_handler(
    State(state): State<AppState>,
    AxumPath(capture_id): AxumPath<String>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences.store.redact_capture(capture_id.trim()) {
        Ok(summary) => Json(summary).into_response(),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_delete_handler(
    State(state): State<AppState>,
    AxumPath(capture_id): AxumPath<String>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    match personal_preferences.store.delete_capture(capture_id.trim()) {
        Ok(summary) => Json(summary).into_response(),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}

pub(crate) async fn personal_preferences_purge_handler(
    State(state): State<AppState>,
    Json(payload): Json<PersonalPreferencesPurgeRequest>,
) -> Response {
    let Some(personal_preferences) = state.personal_preferences.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            personal_preferences_disabled_message(),
        );
    };
    if !personal_preferences.config.purge_enabled {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            "personal preferences purge is disabled; enable [personal_preferences].purge_enabled",
        );
    }
    match personal_preferences
        .store
        .purge_all(payload.include_exports.unwrap_or(false))
    {
        Ok(summary) => Json(summary).into_response(),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        ),
    }
}
