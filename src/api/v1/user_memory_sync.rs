use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;
use tracing::warn;

use crate::auth::{AuthContext, AuthMode};
use crate::error::{ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT, ERR_MISSING_CREDENTIALS};
use crate::http_api::{app_error_response, json_error};
use crate::profiles::embedder::ProfileEmbedding;
use crate::profiles::{Agent, Preference, PreferenceCategory, ProfileEmbedder};
use crate::search::AppState;
use crate::user_memory_sync::{
    decrypt_user_memory_sync_payload_envelope, encrypt_user_memory_sync_payload_envelope,
    parse_lane_names_lossy, resolve_user_memory_sync_payload_encryption_key, stable_content_hash,
    stable_event_id, user_memory_sync_lane_policy, user_memory_sync_now_ms,
    user_memory_sync_payload_encryption_key_configured, user_memory_sync_payload_envelope_mode,
    user_memory_sync_policy_matrix, user_memory_sync_server_principal_key, UserMemorySyncBundle,
    UserMemorySyncEvent, UserMemorySyncIdentity, UserMemorySyncLane, UserMemorySyncLedger,
    UserMemorySyncLedgerSnapshot, UserMemorySyncOperation, UserMemorySyncPayloadEncryptionKey,
    UserMemorySyncPolicyMatrix, UserMemorySyncProvenance, UserMemorySyncSensitivity,
    UserMemorySyncServerAckResult, UserMemorySyncServerDevice, UserMemorySyncServerFeed,
    UserMemorySyncServerPushResult, UserMemorySyncServerSnapshot, UserMemorySyncServerStore,
    UserMemorySyncServerStoredEvent, USER_MEMORY_SYNC_SCHEMA_VERSION,
};

#[derive(Debug, Serialize)]
struct UserMemorySyncStatusResponse {
    schema_version: &'static str,
    enabled: bool,
    mode: &'static str,
    server_base_url: Option<String>,
    api_key_env_configured: bool,
    payload_encryption_key_env_configured: bool,
    identity: UserMemorySyncIdentity,
    device_id_configured: bool,
    device_id: Option<String>,
    enabled_lanes: Vec<UserMemorySyncLane>,
    invalid_config_lanes: Vec<String>,
    supported_lanes: Vec<UserMemorySyncLane>,
    raw_evidence_enabled: bool,
    pull_interval_seconds: u64,
    max_upload_bytes_per_cycle: usize,
    local_sources: UserMemorySyncLocalSources,
    ledger: UserMemorySyncLedgerStatus,
    server_store: UserMemorySyncServerSnapshot,
    policy: UserMemorySyncPolicyMatrix,
}

#[derive(Debug, Serialize)]
struct UserMemorySyncLocalSources {
    repo_memory_available: bool,
    profile_memory_available: bool,
    conversations_available: bool,
    personal_preferences_available: bool,
    generated_skills_available: bool,
}

#[derive(Debug, Serialize)]
struct UserMemorySyncLedgerStatus {
    path: String,
    exists: bool,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct UserMemorySyncDryRunRequest {
    #[serde(default)]
    lanes: Vec<String>,
    #[serde(default)]
    include_optional_sensitive: bool,
    #[serde(default)]
    base_cursor: Option<String>,
    #[serde(default)]
    max_events: Option<usize>,
}

#[derive(Debug, Serialize)]
struct UserMemorySyncDryRunResponse {
    schema_version: &'static str,
    dry_run_only: bool,
    enabled: bool,
    selected_lanes: Vec<UserMemorySyncLane>,
    invalid_config_lanes: Vec<String>,
    include_optional_sensitive_requested: bool,
    raw_evidence_enabled: bool,
    identity: UserMemorySyncIdentity,
    summaries: Vec<UserMemorySyncLaneDryRunSummary>,
    policy: UserMemorySyncPolicyMatrix,
    notes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct UserMemorySyncLaneDryRunSummary {
    lane: UserMemorySyncLane,
    source_available: bool,
    adapter_ready: bool,
    configured_for_upload: bool,
    records: BTreeMap<String, usize>,
    estimated_payload_bytes: Option<usize>,
    sensitive_exclusions: Vec<String>,
    blocked_reason: Option<String>,
    notes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct UserMemorySyncBundleDryRunResponse {
    schema_version: &'static str,
    dry_run_only: bool,
    enabled: bool,
    identity: UserMemorySyncIdentity,
    device_id_configured: bool,
    bundle_id: String,
    device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    base_cursor: Option<String>,
    created_at_ms: i64,
    selected_lanes: Vec<UserMemorySyncLane>,
    invalid_config_lanes: Vec<String>,
    event_count: usize,
    lane_counts: BTreeMap<String, usize>,
    events: Vec<UserMemorySyncBundleEventRef>,
    ledger: UserMemorySyncLedgerSnapshot,
    notes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct UserMemorySyncBundleEventRef {
    event_id: String,
    lane: UserMemorySyncLane,
    operation: UserMemorySyncOperation,
    object_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    object_version: Option<String>,
    content_hash: String,
    sensitivity: UserMemorySyncSensitivity,
    payload_kind: String,
    payload_mode: String,
    payload_encrypted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ledger_status: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct UserMemorySyncRegisterDeviceRequest {
    #[serde(default)]
    device_id: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    enabled_lanes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct UserMemorySyncRegisterDeviceResponse {
    schema_version: &'static str,
    enabled: bool,
    identity: UserMemorySyncIdentity,
    device: UserMemorySyncServerDevice,
    server_store: UserMemorySyncServerSnapshot,
    notes: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct UserMemorySyncPushRequest {
    #[serde(default)]
    schema_version: Option<String>,
    bundle_id: String,
    device_id: String,
    #[serde(default)]
    base_cursor: Option<String>,
    #[serde(default)]
    created_at_ms: Option<i64>,
    #[serde(default)]
    lanes: Vec<UserMemorySyncLane>,
    #[serde(default)]
    events: Vec<UserMemorySyncEvent>,
}

#[derive(Debug, Serialize)]
struct UserMemorySyncPushResponse {
    schema_version: &'static str,
    enabled: bool,
    identity: UserMemorySyncIdentity,
    result: UserMemorySyncServerPushResult,
    ledger: UserMemorySyncLedgerSnapshot,
    server_store: UserMemorySyncServerSnapshot,
    notes: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct UserMemorySyncFeedQuery {
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    lanes: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    exclude_device_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct UserMemorySyncFeedResponse {
    schema_version: &'static str,
    enabled: bool,
    identity: UserMemorySyncIdentity,
    feed: UserMemorySyncServerFeed,
    notes: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct UserMemorySyncAckRequest {
    device_id: String,
    #[serde(default)]
    event_ids: Vec<String>,
    #[serde(default)]
    cursor: Option<String>,
}

#[derive(Debug, Serialize)]
struct UserMemorySyncAckResponse {
    schema_version: &'static str,
    enabled: bool,
    identity: UserMemorySyncIdentity,
    result: UserMemorySyncServerAckResult,
    server_store: UserMemorySyncServerSnapshot,
    notes: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct UserMemorySyncApplyRequest {
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    lanes: Vec<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    device_id: Option<String>,
    #[serde(default)]
    exclude_device_id: Option<String>,
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    ack: Option<bool>,
}

#[derive(Debug, Serialize)]
struct UserMemorySyncApplyResponse {
    schema_version: &'static str,
    enabled: bool,
    identity: UserMemorySyncIdentity,
    dry_run: bool,
    device_id: String,
    selected_lanes: Vec<UserMemorySyncLane>,
    fetched_events: usize,
    applied_event_ids: Vec<String>,
    skipped_events: Vec<UserMemorySyncApplySkippedEvent>,
    failed_events: Vec<UserMemorySyncApplyFailedEvent>,
    profile_import: UserMemorySyncProfileApplySummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ack: Option<UserMemorySyncServerAckResult>,
    ledger: UserMemorySyncLedgerSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
    has_more: bool,
    notes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct UserMemorySyncApplySkippedEvent {
    event_id: String,
    lane: UserMemorySyncLane,
    reason: String,
}

#[derive(Debug, Serialize)]
struct UserMemorySyncApplyFailedEvent {
    event_id: String,
    lane: UserMemorySyncLane,
    error: String,
}

#[derive(Debug, Default, Serialize)]
struct UserMemorySyncProfileApplySummary {
    agents_upserted: usize,
    preferences_inserted: usize,
    preferences_updated: usize,
    preferences_skipped: usize,
    dry_run_profile_events: usize,
}

#[derive(Debug, Clone)]
struct UserMemorySyncResolvedPrincipal {
    key: String,
    identity: UserMemorySyncIdentity,
}

#[derive(Debug, Deserialize)]
struct ProfileAgentSyncPayload {
    #[serde(default)]
    schema_version: Option<String>,
    kind: String,
    id: String,
    role: String,
    created_at: i64,
}

#[derive(Debug, Deserialize)]
struct ProfilePreferenceSyncPayload {
    #[serde(default)]
    schema_version: Option<String>,
    kind: String,
    id: String,
    agent_id: String,
    category: PreferenceCategory,
    content: String,
    last_updated: i64,
}

pub(crate) async fn user_memory_sync_status_handler(State(state): State<AppState>) -> Response {
    match build_status_response(&state) {
        Ok(response) => Json(response).into_response(),
        Err(err) => {
            state.metrics.inc_error();
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                err.to_string(),
            )
        }
    }
}

pub(crate) async fn user_memory_sync_dry_run_handler(
    State(state): State<AppState>,
    Json(body): Json<UserMemorySyncDryRunRequest>,
) -> Response {
    let (configured_lanes, invalid_config_lanes) =
        parse_lane_names_lossy(&state.user_memory_sync.enabled_lanes);
    let selected_lanes = match selected_dry_run_lanes(&state, &body) {
        Ok(lanes) => lanes,
        Err(err) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                err.to_string(),
            );
        }
    };
    let configured_lane_set = configured_lanes.into_iter().collect::<BTreeSet<_>>();
    let mut summaries = Vec::new();
    for lane in selected_lanes.iter().copied() {
        match build_lane_dry_run_summary(&state, lane, &configured_lane_set) {
            Ok(summary) => summaries.push(summary),
            Err(err) => {
                state.metrics.inc_error();
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ERR_INTERNAL_ERROR,
                    err.to_string(),
                );
            }
        }
    }
    let mut notes = vec![
        "Dry-run does not upload data and does not call export routines that write local files."
            .to_string(),
        "Live push, feed, apply, and ack endpoints are available for sanitized event bundles; apply mutates only encrypted profile events in this release."
            .to_string(),
    ];
    if body.include_optional_sensitive && !state.user_memory_sync.raw_evidence_enabled {
        notes.push(
            "Optional sensitive payloads were requested but raw evidence sync is disabled in config."
                .to_string(),
        );
    }
    notes.push(user_memory_sync_identity_note(
        &state.user_memory_sync_identity,
    ));
    Json(UserMemorySyncDryRunResponse {
        schema_version: USER_MEMORY_SYNC_SCHEMA_VERSION,
        dry_run_only: true,
        enabled: state.user_memory_sync.enabled,
        selected_lanes,
        invalid_config_lanes,
        include_optional_sensitive_requested: body.include_optional_sensitive,
        raw_evidence_enabled: state.user_memory_sync.raw_evidence_enabled,
        identity: state.user_memory_sync_identity.clone(),
        summaries,
        policy: user_memory_sync_policy_matrix(),
        notes,
    })
    .into_response()
}

pub(crate) async fn user_memory_sync_bundle_dry_run_handler(
    State(state): State<AppState>,
    Json(body): Json<UserMemorySyncDryRunRequest>,
) -> Response {
    let (_, invalid_config_lanes) = parse_lane_names_lossy(&state.user_memory_sync.enabled_lanes);
    let selected_lanes = match selected_dry_run_lanes(&state, &body) {
        Ok(lanes) => lanes,
        Err(err) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                err.to_string(),
            );
        }
    };
    let (device_id, device_id_configured) = dry_run_device_id(&state);
    let mut notes = vec![
        "Dry-run bundle does not upload data, write export files, write the ledger, ack cursors, or apply remote events."
            .to_string(),
        "Events are returned as ids and hashes only; raw payload content is intentionally omitted."
            .to_string(),
    ];
    let mut events = match build_bundle_events(&state, &selected_lanes, &device_id, &mut notes) {
        Ok(events) => events,
        Err(err) => {
            state.metrics.inc_error();
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                err.to_string(),
            );
        }
    };
    let max_events = body.max_events.unwrap_or(1_000).clamp(1, 5_000);
    if events.len() > max_events {
        notes.push(format!(
            "Event list was truncated from {} to {} by max_events.",
            events.len(),
            max_events
        ));
        events.truncate(max_events);
    }
    if body.include_optional_sensitive && !state.user_memory_sync.raw_evidence_enabled {
        notes.push(
            "Optional sensitive payloads were requested but raw evidence sync is disabled in config."
                .to_string(),
        );
    }
    notes.push(user_memory_sync_identity_note(
        &state.user_memory_sync_identity,
    ));

    let created_at_ms = user_memory_sync_now_ms();
    let bundle = UserMemorySyncBundle::new(
        device_id.clone(),
        body.base_cursor.clone(),
        created_at_ms,
        selected_lanes.clone(),
        events,
    );
    let state_dir = user_memory_sync_state_dir(&state);
    let ledger_path = UserMemorySyncLedger::path_for_state_dir(&state_dir);
    let ledger_snapshot =
        match UserMemorySyncLedger::snapshot_for_events_read_only(&ledger_path, &bundle.events) {
            Ok(snapshot) => snapshot,
            Err(err) => {
                state.metrics.inc_error();
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ERR_INTERNAL_ERROR,
                    err.to_string(),
                );
            }
        };
    let ledger_states =
        match UserMemorySyncLedger::event_states_read_only(&ledger_path, &bundle.events) {
            Ok(states) => states,
            Err(err) => {
                state.metrics.inc_error();
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ERR_INTERNAL_ERROR,
                    err.to_string(),
                );
            }
        };
    let mut lane_counts = BTreeMap::new();
    for event in &bundle.events {
        *lane_counts
            .entry(event.lane.as_str().to_string())
            .or_insert(0) += 1;
    }
    let event_refs = bundle
        .events
        .iter()
        .map(|event| UserMemorySyncBundleEventRef {
            event_id: event.event_id.clone(),
            lane: event.lane,
            operation: event.operation,
            object_id: event.object_id.clone(),
            object_version: event.object_version.clone(),
            content_hash: event.content_hash.clone(),
            sensitivity: event.sensitivity,
            payload_kind: event.payload_kind.clone(),
            payload_mode: user_memory_sync_payload_envelope_mode(event.payload_envelope.as_ref()),
            payload_encrypted: event
                .payload_envelope
                .as_ref()
                .is_some_and(|envelope| envelope.is_encrypted()),
            ledger_status: ledger_states
                .get(&event.event_id)
                .and_then(|state| state.status.clone()),
        })
        .collect::<Vec<_>>();

    Json(UserMemorySyncBundleDryRunResponse {
        schema_version: USER_MEMORY_SYNC_SCHEMA_VERSION,
        dry_run_only: true,
        enabled: state.user_memory_sync.enabled,
        identity: state.user_memory_sync_identity.clone(),
        device_id_configured,
        bundle_id: bundle.bundle_id,
        device_id: bundle.device_id,
        base_cursor: bundle.base_cursor,
        created_at_ms: bundle.created_at_ms,
        selected_lanes,
        invalid_config_lanes,
        event_count: event_refs.len(),
        lane_counts,
        events: event_refs,
        ledger: ledger_snapshot,
        notes,
    })
    .into_response()
}

pub(crate) async fn user_memory_sync_device_register_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UserMemorySyncRegisterDeviceRequest>,
) -> Response {
    let principal = match user_memory_sync_request_principal(&state, &headers).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let device_id = match request_device_id(body.device_id.as_deref(), &state) {
        Ok(device_id) => device_id,
        Err(err) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                err.to_string(),
            );
        }
    };
    let enabled_lanes = match registration_lanes(&state, &body.enabled_lanes) {
        Ok(lanes) => lanes,
        Err(err) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                err.to_string(),
            );
        }
    };
    let display_name = body.display_name.as_deref().and_then(trimmed_owned);
    let state_dir = user_memory_sync_state_dir(&state);
    let store_path = UserMemorySyncServerStore::path_for_state_dir(&state_dir);
    let store = match UserMemorySyncServerStore::open_or_create(&store_path) {
        Ok(store) => store,
        Err(err) => {
            state.metrics.inc_error();
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                err.to_string(),
            );
        }
    };
    let now_ms = user_memory_sync_now_ms();
    let device = match store.register_device(
        &principal.key,
        &device_id,
        display_name,
        enabled_lanes,
        now_ms,
    ) {
        Ok(device) => device,
        Err(err) => {
            state.metrics.inc_error();
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                err.to_string(),
            );
        }
    };
    let server_store =
        match UserMemorySyncServerStore::snapshot_read_only(&store_path, &principal.key) {
            Ok(snapshot) => snapshot,
            Err(err) => {
                state.metrics.inc_error();
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ERR_INTERNAL_ERROR,
                    err.to_string(),
                );
            }
        };
    Json(UserMemorySyncRegisterDeviceResponse {
        schema_version: USER_MEMORY_SYNC_SCHEMA_VERSION,
        enabled: state.user_memory_sync.enabled,
        identity: principal.identity.clone(),
        device,
        server_store,
        notes: vec![user_memory_sync_identity_note(&principal.identity)],
    })
    .into_response()
}

pub(crate) async fn user_memory_sync_push_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UserMemorySyncPushRequest>,
) -> Response {
    let principal = match user_memory_sync_request_principal(&state, &headers).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let bundle = match push_request_bundle(body) {
        Ok(bundle) => bundle,
        Err(err) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                err.to_string(),
            );
        }
    };
    let state_dir = user_memory_sync_state_dir(&state);
    let store_path = UserMemorySyncServerStore::path_for_state_dir(&state_dir);
    let store = match UserMemorySyncServerStore::open_or_create(&store_path) {
        Ok(store) => store,
        Err(err) => {
            state.metrics.inc_error();
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                err.to_string(),
            );
        }
    };
    let now_ms = user_memory_sync_now_ms();
    if let Err(err) = store.register_device(
        &principal.key,
        &bundle.device_id,
        None,
        bundle.lanes.clone(),
        now_ms,
    ) {
        state.metrics.inc_error();
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            err.to_string(),
        );
    }
    let result = match store.push_bundle(&principal.key, &bundle, now_ms) {
        Ok(result) => result,
        Err(err) => {
            state.metrics.inc_error();
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                err.to_string(),
            );
        }
    };
    if !result.accepted_event_ids.is_empty() {
        let accepted_set = result
            .accepted_event_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let accepted_events = bundle
            .events
            .iter()
            .filter(|event| accepted_set.contains(&event.event_id))
            .cloned()
            .collect::<Vec<_>>();
        let ledger_path = UserMemorySyncLedger::path_for_state_dir(&state_dir);
        match UserMemorySyncLedger::open_or_create(&ledger_path)
            .and_then(|ledger| ledger.record_uploaded(&accepted_events, now_ms).map(|_| ()))
        {
            Ok(_) => {}
            Err(err) => {
                state.metrics.inc_error();
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ERR_INTERNAL_ERROR,
                    err.to_string(),
                );
            }
        }
    }
    let ledger_path = UserMemorySyncLedger::path_for_state_dir(&state_dir);
    let ledger =
        match UserMemorySyncLedger::snapshot_for_events_read_only(&ledger_path, &bundle.events) {
            Ok(snapshot) => snapshot,
            Err(err) => {
                state.metrics.inc_error();
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ERR_INTERNAL_ERROR,
                    err.to_string(),
                );
            }
        };
    let server_store =
        match UserMemorySyncServerStore::snapshot_read_only(&store_path, &principal.key) {
            Ok(snapshot) => snapshot,
            Err(err) => {
                state.metrics.inc_error();
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ERR_INTERNAL_ERROR,
                    err.to_string(),
                );
            }
        };
    Json(UserMemorySyncPushResponse {
        schema_version: USER_MEMORY_SYNC_SCHEMA_VERSION,
        enabled: state.user_memory_sync.enabled,
        identity: principal.identity.clone(),
        result,
        ledger,
        server_store,
        notes: vec![
            "Accepted events were stored in the per-user server feed keyed by the resolved user principal.".to_string(),
            "Payloads must be summary-only or encrypted envelopes; cleartext payload envelopes are rejected before storage.".to_string(),
            "Raw credentials are not stored or returned by this endpoint.".to_string(),
        ],
    })
    .into_response()
}

pub(crate) async fn user_memory_sync_feed_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<UserMemorySyncFeedQuery>,
) -> Response {
    let principal = match user_memory_sync_request_principal(&state, &headers).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let lanes = match parse_lane_csv(query.lanes.as_deref()) {
        Ok(lanes) => lanes,
        Err(err) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                err.to_string(),
            );
        }
    };
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let state_dir = user_memory_sync_state_dir(&state);
    let store_path = UserMemorySyncServerStore::path_for_state_dir(&state_dir);
    let store = match UserMemorySyncServerStore::open_or_create(&store_path) {
        Ok(store) => store,
        Err(err) => {
            state.metrics.inc_error();
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                err.to_string(),
            );
        }
    };
    let feed = match store.feed(
        &principal.key,
        query.cursor.as_deref(),
        &lanes,
        limit,
        query.exclude_device_id.as_deref(),
    ) {
        Ok(feed) => feed,
        Err(err) => {
            let message = err.to_string();
            let status = if message.contains("cursor") {
                StatusCode::BAD_REQUEST
            } else {
                state.metrics.inc_error();
                StatusCode::INTERNAL_SERVER_ERROR
            };
            let code = if status == StatusCode::BAD_REQUEST {
                ERR_INVALID_ARGUMENT
            } else {
                ERR_INTERNAL_ERROR
            };
            return json_error(status, code, message);
        }
    };
    Json(UserMemorySyncFeedResponse {
        schema_version: USER_MEMORY_SYNC_SCHEMA_VERSION,
        enabled: state.user_memory_sync.enabled,
        identity: principal.identity.clone(),
        feed,
        notes: vec![
            "Feed events are scoped to the resolved user identity and can be filtered by lane or source device.".to_string(),
            "Encrypted payload envelopes are returned opaque for local devices; the apply endpoint decrypts and merges supported profile events.".to_string(),
            "Unsupported lanes remain explicit no-op skips until they have lane-specific safe importers.".to_string(),
        ],
    })
    .into_response()
}

pub(crate) async fn user_memory_sync_ack_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UserMemorySyncAckRequest>,
) -> Response {
    let principal = match user_memory_sync_request_principal(&state, &headers).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    if body.event_ids.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "event_ids must not be empty",
        );
    }
    let device_id = match request_device_id(Some(&body.device_id), &state) {
        Ok(device_id) => device_id,
        Err(err) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                err.to_string(),
            );
        }
    };
    let state_dir = user_memory_sync_state_dir(&state);
    let store_path = UserMemorySyncServerStore::path_for_state_dir(&state_dir);
    let store = match UserMemorySyncServerStore::open_or_create(&store_path) {
        Ok(store) => store,
        Err(err) => {
            state.metrics.inc_error();
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                err.to_string(),
            );
        }
    };
    let now_ms = user_memory_sync_now_ms();
    let result = match store.ack(
        &principal.key,
        &device_id,
        &body.event_ids,
        body.cursor.clone(),
        now_ms,
    ) {
        Ok(result) => result,
        Err(err) => {
            let message = err.to_string();
            let status = if message.contains("cursor") || message.contains("device_id") {
                StatusCode::BAD_REQUEST
            } else {
                state.metrics.inc_error();
                StatusCode::INTERNAL_SERVER_ERROR
            };
            let code = if status == StatusCode::BAD_REQUEST {
                ERR_INVALID_ARGUMENT
            } else {
                ERR_INTERNAL_ERROR
            };
            return json_error(status, code, message);
        }
    };
    let server_store =
        match UserMemorySyncServerStore::snapshot_read_only(&store_path, &principal.key) {
            Ok(snapshot) => snapshot,
            Err(err) => {
                state.metrics.inc_error();
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ERR_INTERNAL_ERROR,
                    err.to_string(),
                );
            }
        };
    Json(UserMemorySyncAckResponse {
        schema_version: USER_MEMORY_SYNC_SCHEMA_VERSION,
        enabled: state.user_memory_sync.enabled,
        identity: principal.identity.clone(),
        result,
        server_store,
        notes: vec![
            "Ack records mark which local device consumed events from the per-user server feed.".to_string(),
            "Ack alone does not apply remote events into local source stores; use the apply endpoint for local down-sync handling.".to_string(),
        ],
    })
    .into_response()
}

pub(crate) async fn user_memory_sync_apply_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UserMemorySyncApplyRequest>,
) -> Response {
    let principal = match user_memory_sync_request_principal(&state, &headers).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let device_id = match request_device_id(body.device_id.as_deref(), &state) {
        Ok(device_id) => device_id,
        Err(err) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                err.to_string(),
            );
        }
    };
    let selected_lanes = match selected_apply_lanes(&state, &body.lanes) {
        Ok(lanes) => lanes,
        Err(err) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                err.to_string(),
            );
        }
    };
    let exclude_device_id = body
        .exclude_device_id
        .as_deref()
        .and_then(trimmed_owned)
        .unwrap_or_else(|| device_id.clone());
    let limit = body.limit.unwrap_or(100).clamp(1, 500);
    let state_dir = user_memory_sync_state_dir(&state);
    let store_path = UserMemorySyncServerStore::path_for_state_dir(&state_dir);
    let store = match UserMemorySyncServerStore::open_or_create(&store_path) {
        Ok(store) => store,
        Err(err) => {
            state.metrics.inc_error();
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                err.to_string(),
            );
        }
    };
    let feed = match store.feed(
        &principal.key,
        body.cursor.as_deref(),
        &selected_lanes,
        limit,
        Some(&exclude_device_id),
    ) {
        Ok(feed) => feed,
        Err(err) => {
            let message = err.to_string();
            let status = if message.contains("cursor") {
                StatusCode::BAD_REQUEST
            } else {
                state.metrics.inc_error();
                StatusCode::INTERNAL_SERVER_ERROR
            };
            let code = if status == StatusCode::BAD_REQUEST {
                ERR_INVALID_ARGUMENT
            } else {
                ERR_INTERNAL_ERROR
            };
            return json_error(status, code, message);
        }
    };
    let payload_encryption_key = match resolve_user_memory_sync_payload_encryption_key(
        state.user_memory_sync.encryption_key_env.as_deref(),
    ) {
        Ok(key) => key,
        Err(err) => {
            return json_error(
                StatusCode::PRECONDITION_FAILED,
                ERR_MISSING_CREDENTIALS,
                err.to_string(),
            );
        }
    };
    let mut applied_stored_events = Vec::new();
    let mut skipped_stored_events = Vec::new();
    let mut failed_events = Vec::new();
    let mut skipped_events = Vec::new();
    let mut profile_import = UserMemorySyncProfileApplySummary::default();

    for stored in &feed.events {
        match apply_user_memory_sync_event(
            &state,
            stored,
            payload_encryption_key.as_ref(),
            body.dry_run,
            &mut profile_import,
        )
        .await
        {
            Ok(None) => applied_stored_events.push(stored.clone()),
            Ok(Some(reason)) => {
                skipped_events.push(UserMemorySyncApplySkippedEvent {
                    event_id: stored.event.event_id.clone(),
                    lane: stored.event.lane,
                    reason,
                });
                skipped_stored_events.push(stored.clone());
            }
            Err(err) => failed_events.push(UserMemorySyncApplyFailedEvent {
                event_id: stored.event.event_id.clone(),
                lane: stored.event.lane,
                error: err.to_string(),
            }),
        }
    }

    let now_ms = user_memory_sync_now_ms();
    if !body.dry_run {
        let ledger_path = UserMemorySyncLedger::path_for_state_dir(&state_dir);
        let ledger = match UserMemorySyncLedger::open_or_create(&ledger_path) {
            Ok(ledger) => ledger,
            Err(err) => {
                state.metrics.inc_error();
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ERR_INTERNAL_ERROR,
                    err.to_string(),
                );
            }
        };
        if let Err(err) = ledger.record_applied(&applied_stored_events, now_ms) {
            state.metrics.inc_error();
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                err.to_string(),
            );
        }
        if let Err(err) = ledger.record_skipped(&skipped_stored_events, now_ms) {
            state.metrics.inc_error();
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                err.to_string(),
            );
        }
    }

    let mut ack_result = None;
    let ack_after_apply = body.ack.unwrap_or(true);
    if !body.dry_run && ack_after_apply {
        let mut event_ids = applied_stored_events
            .iter()
            .chain(skipped_stored_events.iter())
            .map(|stored| stored.event.event_id.clone())
            .collect::<Vec<_>>();
        event_ids.sort();
        event_ids.dedup();
        if !event_ids.is_empty() {
            match store.ack(
                &principal.key,
                &device_id,
                &event_ids,
                feed.next_cursor.clone(),
                now_ms,
            ) {
                Ok(result) => ack_result = Some(result),
                Err(err) => {
                    state.metrics.inc_error();
                    return json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        ERR_INTERNAL_ERROR,
                        err.to_string(),
                    );
                }
            }
        }
    }

    let feed_events = feed
        .events
        .iter()
        .map(|stored| stored.event.clone())
        .collect::<Vec<_>>();
    let ledger_path = UserMemorySyncLedger::path_for_state_dir(&state_dir);
    let ledger =
        match UserMemorySyncLedger::snapshot_for_events_read_only(&ledger_path, &feed_events) {
            Ok(snapshot) => snapshot,
            Err(err) => {
                state.metrics.inc_error();
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ERR_INTERNAL_ERROR,
                    err.to_string(),
                );
            }
        };
    let mut notes = vec![
        "Apply reads the per-user server feed, excludes this local device by default, and only acks events that were applied or intentionally skipped.".to_string(),
        "Profile-memory payloads are decrypted locally and embedded with the local profile embedder or deterministic fallback before import.".to_string(),
        "Lanes without a safe local importer are recorded as skipped and acked so the feed cursor can advance without mutating local stores.".to_string(),
    ];
    if payload_encryption_key.is_none() {
        notes.push(
            "No user-memory sync encryption key material is available; encrypted payload events cannot be applied."
                .to_string(),
        );
    }
    if body.dry_run {
        notes.push(
            "Dry-run did not mutate profile memory, ledger state, or server ack state.".to_string(),
        );
    }
    Json(UserMemorySyncApplyResponse {
        schema_version: USER_MEMORY_SYNC_SCHEMA_VERSION,
        enabled: state.user_memory_sync.enabled,
        identity: principal.identity.clone(),
        dry_run: body.dry_run,
        device_id,
        selected_lanes,
        fetched_events: feed.events.len(),
        applied_event_ids: applied_stored_events
            .iter()
            .map(|stored| stored.event.event_id.clone())
            .collect(),
        skipped_events,
        failed_events,
        profile_import,
        ack: ack_result,
        ledger,
        next_cursor: feed.next_cursor,
        has_more: feed.has_more,
        notes,
    })
    .into_response()
}

fn build_status_response(state: &AppState) -> Result<UserMemorySyncStatusResponse> {
    let (enabled_lanes, invalid_config_lanes) =
        parse_lane_names_lossy(&state.user_memory_sync.enabled_lanes);
    let state_dir = user_memory_sync_state_dir(state);
    let ledger_path = UserMemorySyncLedger::path_for_state_dir(&state_dir);
    let server_store = server_store_snapshot(state, &state_dir)?;
    Ok(UserMemorySyncStatusResponse {
        schema_version: USER_MEMORY_SYNC_SCHEMA_VERSION,
        enabled: state.user_memory_sync.enabled,
        mode: if state.user_memory_sync.enabled {
            "configured_local_server_store"
        } else {
            "disabled"
        },
        server_base_url: state.user_memory_sync.server_base_url.clone(),
        api_key_env_configured: state.user_memory_sync.api_key_env.is_some(),
        payload_encryption_key_env_configured: user_memory_sync_payload_encryption_key_configured(
            state.user_memory_sync.encryption_key_env.as_deref(),
        ),
        identity: state.user_memory_sync_identity.clone(),
        device_id_configured: state.user_memory_sync.device_id.is_some(),
        device_id: state.user_memory_sync.device_id.clone(),
        enabled_lanes,
        invalid_config_lanes,
        supported_lanes: UserMemorySyncLane::supported_lanes(),
        raw_evidence_enabled: state.user_memory_sync.raw_evidence_enabled,
        pull_interval_seconds: state.user_memory_sync.pull_interval_seconds,
        max_upload_bytes_per_cycle: state.user_memory_sync.max_upload_bytes_per_cycle,
        local_sources: UserMemorySyncLocalSources {
            repo_memory_available: state.memory.is_some(),
            profile_memory_available: state.profile_state.is_some(),
            conversations_available: state.conversations.is_some(),
            personal_preferences_available: state.personal_preferences.is_some(),
            generated_skills_available: state.personal_preferences.is_some(),
        },
        ledger: UserMemorySyncLedgerStatus {
            path: ledger_path.display().to_string(),
            exists: ledger_path.exists(),
        },
        server_store,
        policy: user_memory_sync_policy_matrix(),
    })
}

async fn user_memory_sync_request_principal(
    state: &AppState,
    headers: &HeaderMap,
) -> std::result::Result<UserMemorySyncResolvedPrincipal, Response> {
    if !state.user_memory_sync.enabled {
        return Err(json_error(
            StatusCode::PRECONDITION_FAILED,
            ERR_INVALID_ARGUMENT,
            "user-memory sync is disabled",
        ));
    }

    if state.auth.has_deferred_route_credential(headers) {
        let ctx = state
            .auth
            .authenticate_user_memory_sync(headers)
            .await
            .map_err(|err| app_error_response(&err))?;
        return Ok(UserMemorySyncResolvedPrincipal {
            key: auth_context_user_memory_sync_principal_key(&ctx),
            identity: auth_context_user_memory_sync_identity(&ctx),
        });
    }

    if matches!(state.auth.config().mode, AuthMode::ExternalOnly)
        && state.auth.config().external_api_key_introspection.enabled
    {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            ERR_MISSING_CREDENTIALS,
            "request API key is required for hosted user-memory sync",
        ));
    }

    user_memory_sync_server_principal_key(&state.user_memory_sync_identity)
        .map(|key| UserMemorySyncResolvedPrincipal {
            key,
            identity: state.user_memory_sync_identity.clone(),
        })
        .ok_or_else(|| {
            json_error(
                StatusCode::UNAUTHORIZED,
                ERR_MISSING_CREDENTIALS,
                "configured mswarm API key is required for per-user memory sync",
            )
        })
}

fn auth_context_user_memory_sync_principal_key(ctx: &AuthContext) -> String {
    let content_hash = stable_content_hash(&json!({
        "issuer": ctx.issuer,
        "principal_id": ctx.principal_id,
    }))
    .unwrap_or_else(|_| format!("sha256:{}", ctx.credential_fingerprint));
    format!("auth_principal:{content_hash}")
}

fn auth_context_user_memory_sync_identity(ctx: &AuthContext) -> UserMemorySyncIdentity {
    UserMemorySyncIdentity {
        source: format!("request.auth.{}", ctx.issuer),
        configured: true,
        credential_fingerprint: Some(ctx.credential_fingerprint.clone()),
        principal_resolution: "mswarm_api_key_server_introspection".to_string(),
        raw_credential_returned: false,
    }
}

fn server_store_snapshot(
    state: &AppState,
    state_dir: &PathBuf,
) -> Result<UserMemorySyncServerSnapshot> {
    let store_path = UserMemorySyncServerStore::path_for_state_dir(state_dir);
    let Some(principal_key) =
        user_memory_sync_server_principal_key(&state.user_memory_sync_identity)
    else {
        return Ok(UserMemorySyncServerSnapshot {
            path: store_path.display().to_string(),
            exists: store_path.exists(),
            devices: 0,
            events: 0,
            latest_cursor: None,
        });
    };
    UserMemorySyncServerStore::snapshot_read_only(store_path, &principal_key)
}

fn request_device_id(request_device_id: Option<&str>, state: &AppState) -> Result<String> {
    request_device_id
        .and_then(trimmed_owned)
        .or_else(|| {
            state
                .user_memory_sync
                .device_id
                .as_deref()
                .and_then(trimmed_owned)
        })
        .ok_or_else(|| anyhow!("device_id is required"))
}

fn registration_lanes(
    state: &AppState,
    requested_lanes: &[String],
) -> Result<Vec<UserMemorySyncLane>> {
    if !requested_lanes.is_empty() {
        return parse_lane_names_strict(requested_lanes);
    }
    if !state.user_memory_sync.enabled_lanes.is_empty() {
        return parse_lane_names_strict(&state.user_memory_sync.enabled_lanes);
    }
    Ok(Vec::new())
}

fn push_request_bundle(body: UserMemorySyncPushRequest) -> Result<UserMemorySyncBundle> {
    let schema_version = body
        .schema_version
        .as_deref()
        .and_then(stripped_nonempty)
        .unwrap_or(USER_MEMORY_SYNC_SCHEMA_VERSION);
    if schema_version != USER_MEMORY_SYNC_SCHEMA_VERSION {
        return Err(anyhow!(
            "unsupported user-memory sync schema version: {}",
            schema_version
        ));
    }
    let bundle_id =
        trimmed_owned(&body.bundle_id).ok_or_else(|| anyhow!("bundle_id is required"))?;
    let device_id =
        trimmed_owned(&body.device_id).ok_or_else(|| anyhow!("device_id is required"))?;
    if body.events.is_empty() {
        return Err(anyhow!("events must not be empty"));
    }
    if body.events.len() > 5_000 {
        return Err(anyhow!("events exceeds the 5000 event limit"));
    }
    let mut lanes = body.lanes;
    if lanes.is_empty() {
        let mut seen = BTreeSet::new();
        for event in &body.events {
            if seen.insert(event.lane) {
                lanes.push(event.lane);
            }
        }
    }
    if lanes.is_empty() {
        return Err(anyhow!("at least one lane is required"));
    }
    Ok(UserMemorySyncBundle {
        schema_version: USER_MEMORY_SYNC_SCHEMA_VERSION,
        bundle_id,
        device_id,
        base_cursor: body.base_cursor.and_then(|cursor| trimmed_owned(&cursor)),
        created_at_ms: body.created_at_ms.unwrap_or_else(user_memory_sync_now_ms),
        lanes,
        events: body.events,
    })
}

fn parse_lane_csv(value: Option<&str>) -> Result<Vec<UserMemorySyncLane>> {
    let Some(value) = value.and_then(stripped_nonempty) else {
        return Ok(Vec::new());
    };
    let names = value
        .split(',')
        .filter_map(trimmed_owned)
        .collect::<Vec<_>>();
    if names.is_empty() {
        return Ok(Vec::new());
    }
    parse_lane_names_strict(&names)
}

fn stripped_nonempty(value: &str) -> Option<&str> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn trimmed_owned(value: &str) -> Option<String> {
    stripped_nonempty(value).map(ToOwned::to_owned)
}

fn user_memory_sync_identity_note(identity: &UserMemorySyncIdentity) -> String {
    if identity.configured {
        format!(
            "User identity will be resolved by server-side mswarm API-key introspection from {}; raw credentials are not included in this response.",
            identity.source
        )
    } else {
        "No mswarm API-key identity credential is configured for user-memory sync.".to_string()
    }
}

fn user_memory_sync_state_dir(state: &AppState) -> PathBuf {
    state
        .global_state_dir
        .clone()
        .or_else(|| {
            crate::repo_manager::split_scoped_state_dir(state.indexer.state_dir())
                .map(|(base_dir, _, _)| base_dir)
        })
        .unwrap_or_else(|| state.indexer.state_dir().to_path_buf())
}

fn dry_run_device_id(state: &AppState) -> (String, bool) {
    match state
        .user_memory_sync
        .device_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(device_id) => (device_id.to_string(), true),
        None => ("unconfigured_local_device".to_string(), false),
    }
}

fn selected_dry_run_lanes(
    state: &AppState,
    body: &UserMemorySyncDryRunRequest,
) -> Result<Vec<UserMemorySyncLane>> {
    if !body.lanes.is_empty() {
        return parse_lane_names_strict(&body.lanes);
    }
    if !state.user_memory_sync.enabled_lanes.is_empty() {
        return parse_lane_names_strict(&state.user_memory_sync.enabled_lanes);
    }
    Ok(UserMemorySyncLane::supported_lanes())
}

fn selected_apply_lanes(
    state: &AppState,
    requested_lanes: &[String],
) -> Result<Vec<UserMemorySyncLane>> {
    if !requested_lanes.is_empty() {
        return parse_lane_names_strict(requested_lanes);
    }
    if !state.user_memory_sync.enabled_lanes.is_empty() {
        return parse_lane_names_strict(&state.user_memory_sync.enabled_lanes);
    }
    Ok(vec![UserMemorySyncLane::ProfileMemory])
}

fn parse_lane_names_strict(names: &[String]) -> Result<Vec<UserMemorySyncLane>> {
    let mut lanes = Vec::new();
    let mut seen = BTreeSet::new();
    for name in names {
        let lane = UserMemorySyncLane::from_str(name)?;
        if seen.insert(lane) {
            lanes.push(lane);
        }
    }
    if lanes.is_empty() {
        return Err(anyhow!("at least one lane is required"));
    }
    Ok(lanes)
}

async fn apply_user_memory_sync_event(
    state: &AppState,
    stored: &UserMemorySyncServerStoredEvent,
    payload_encryption_key: Option<&UserMemorySyncPayloadEncryptionKey>,
    dry_run: bool,
    profile_import: &mut UserMemorySyncProfileApplySummary,
) -> Result<Option<String>> {
    let event = &stored.event;
    if event.operation != UserMemorySyncOperation::Upsert {
        return Ok(Some(format!(
            "operation {} is not supported by local apply yet",
            event.operation.as_str()
        )));
    }
    match event.lane {
        UserMemorySyncLane::ProfileMemory => {
            apply_profile_memory_sync_event(
                state,
                event,
                payload_encryption_key,
                dry_run,
                profile_import,
            )
            .await
        }
        UserMemorySyncLane::PersonalPreferences
        | UserMemorySyncLane::MindClone
        | UserMemorySyncLane::GeneratedSkills => Ok(Some(
            "lane event is inventory-only in this release; no safe local importer exists yet"
                .to_string(),
        )),
        UserMemorySyncLane::RepoMemory
        | UserMemorySyncLane::Diary
        | UserMemorySyncLane::ConversationSummaries
        | UserMemorySyncLane::TemporalKg => Ok(Some(
            "lane policy is modeled but local down-sync importer is not implemented yet"
                .to_string(),
        )),
    }
}

async fn apply_profile_memory_sync_event(
    state: &AppState,
    event: &UserMemorySyncEvent,
    payload_encryption_key: Option<&UserMemorySyncPayloadEncryptionKey>,
    dry_run: bool,
    profile_import: &mut UserMemorySyncProfileApplySummary,
) -> Result<Option<String>> {
    let Some(profile_state) = state.profile_state.as_ref() else {
        return Ok(Some("profile memory is disabled locally".to_string()));
    };
    let Some(envelope) = event.payload_envelope.as_ref() else {
        return Ok(Some(
            "profile event has summary-only payload; encrypted payload is required for local apply"
                .to_string(),
        ));
    };
    if envelope.is_summary_only() {
        return Ok(Some(
            "profile event has summary-only payload; encrypted payload is required for local apply"
                .to_string(),
        ));
    }
    let Some(payload_encryption_key) = payload_encryption_key else {
        return Err(anyhow!(
            "configured user-memory sync encryption key is required to apply encrypted profile events"
        ));
    };
    match event.payload_kind.as_str() {
        "profile_agent" => {
            let payload: ProfileAgentSyncPayload = decrypt_user_memory_sync_payload_envelope(
                payload_encryption_key,
                event.lane,
                event.operation,
                &event.object_id,
                event.object_version.as_deref(),
                &event.payload_kind,
                envelope,
            )?;
            validate_profile_payload_schema(payload.schema_version.as_deref())?;
            if payload.kind != "profile_agent" {
                return Err(anyhow!(
                    "profile payload kind mismatch: expected profile_agent, got {}",
                    payload.kind
                ));
            }
            let agent_id = stripped_nonempty(&payload.id)
                .ok_or_else(|| anyhow!("profile agent id is required"))?;
            let role = stripped_nonempty(&payload.role).unwrap_or("custom");
            profile_import.dry_run_profile_events += usize::from(dry_run);
            if dry_run {
                return Ok(None);
            }
            profile_state
                .manager
                .create_agent(agent_id, role, payload.created_at)
                .context("apply profile agent sync event")?;
            profile_import.agents_upserted += 1;
            Ok(None)
        }
        "profile_preference" => {
            let payload: ProfilePreferenceSyncPayload = decrypt_user_memory_sync_payload_envelope(
                payload_encryption_key,
                event.lane,
                event.operation,
                &event.object_id,
                event.object_version.as_deref(),
                &event.payload_kind,
                envelope,
            )?;
            validate_profile_payload_schema(payload.schema_version.as_deref())?;
            if payload.kind != "profile_preference" {
                return Err(anyhow!(
                    "profile payload kind mismatch: expected profile_preference, got {}",
                    payload.kind
                ));
            }
            let pref_id = stripped_nonempty(&payload.id)
                .ok_or_else(|| anyhow!("profile preference id is required"))?;
            let agent_id = stripped_nonempty(&payload.agent_id)
                .ok_or_else(|| anyhow!("profile preference agent_id is required"))?;
            let content = stripped_nonempty(&payload.content)
                .ok_or_else(|| anyhow!("profile preference content is required"))?;
            profile_import.dry_run_profile_events += usize::from(dry_run);
            if dry_run {
                return Ok(None);
            }
            let agent = match profile_state.manager.get_agent(agent_id)? {
                Some(agent) => agent,
                None => Agent {
                    id: agent_id.to_string(),
                    role: "custom".to_string(),
                    created_at: payload.last_updated,
                },
            };
            let embedding = profile_apply_embedding(state, content).await;
            let preference = Preference {
                id: pref_id.to_string(),
                agent_id: agent_id.to_string(),
                content: content.to_string(),
                embedding: Some(embedding.embedding),
                embedding_provider: Some(embedding.provider),
                embedding_model: Some(embedding.model),
                embedding_dim: Some(profile_state.manager.embedding_dim()),
                category: payload.category,
                last_updated: payload.last_updated,
            };
            let summary = profile_state
                .manager
                .import_preferences(&[agent], &[preference])
                .context("apply profile preference sync event")?;
            profile_import.agents_upserted += summary.agents;
            profile_import.preferences_inserted += summary.inserted;
            profile_import.preferences_updated += summary.updated;
            profile_import.preferences_skipped += summary.skipped;
            if summary.inserted == 0 && summary.updated == 0 {
                return Ok(Some(
                    "local profile preference is newer or equal by last_updated".to_string(),
                ));
            }
            Ok(None)
        }
        other => Ok(Some(format!(
            "profile payload kind {other} is not supported by local apply"
        ))),
    }
}

async fn profile_apply_embedding(state: &AppState, content: &str) -> ProfileEmbedding {
    let Some(profile_state) = state.profile_state.as_ref() else {
        return ProfileEmbedding {
            embedding: Vec::new(),
            provider: "fallback".to_string(),
            model: "hash-embed-v1".to_string(),
        };
    };
    if let Some(embedder) = profile_state.embedder.as_ref() {
        match embedder.embed_with_metadata(content).await {
            Ok(embedding) => return embedding,
            Err(err) => {
                state.metrics.inc_error();
                warn!(
                    target: "docdexd",
                    error = ?err,
                    "profile apply embedding failed; falling back to local hash"
                );
            }
        }
    }
    ProfileEmbedding {
        embedding: ProfileEmbedder::fallback_embedding(
            content,
            profile_state.manager.embedding_dim(),
        ),
        provider: "fallback".to_string(),
        model: "hash-embed-v1".to_string(),
    }
}

fn validate_profile_payload_schema(schema_version: Option<&str>) -> Result<()> {
    if let Some(schema_version) = schema_version.and_then(stripped_nonempty) {
        if schema_version != USER_MEMORY_SYNC_SCHEMA_VERSION {
            return Err(anyhow!(
                "unsupported profile sync payload schema_version: {}",
                schema_version
            ));
        }
    }
    Ok(())
}

fn build_bundle_events(
    state: &AppState,
    selected_lanes: &[UserMemorySyncLane],
    device_id: &str,
    notes: &mut Vec<String>,
) -> Result<Vec<UserMemorySyncEvent>> {
    let (configured_lanes, _) = parse_lane_names_lossy(&state.user_memory_sync.enabled_lanes);
    let configured_lane_set = configured_lanes.into_iter().collect::<BTreeSet<_>>();
    let payload_encryption_key = resolve_user_memory_sync_payload_encryption_key(
        state.user_memory_sync.encryption_key_env.as_deref(),
    )?;
    if payload_encryption_key.is_some() {
        notes.push(
            "Local bundle events include opaque encrypted payload envelopes from the configured user-memory sync encryption key."
                .to_string(),
        );
    } else {
        notes.push(
            "No user-memory sync encryption key env is configured; local bundle events remain summary-only."
                .to_string(),
        );
    }
    let mut events = Vec::new();
    for lane in selected_lanes {
        match lane {
            UserMemorySyncLane::ProfileMemory => append_profile_bundle_events(
                state,
                device_id,
                payload_encryption_key.as_ref(),
                &mut events,
                notes,
            )?,
            UserMemorySyncLane::PersonalPreferences
            | UserMemorySyncLane::MindClone
            | UserMemorySyncLane::GeneratedSkills => append_inventory_bundle_event(
                state,
                *lane,
                &configured_lane_set,
                device_id,
                payload_encryption_key.as_ref(),
                &mut events,
                notes,
            )?,
            UserMemorySyncLane::RepoMemory => notes.push(
                "Repo-memory bundle events are not emitted yet; repo identity and supersession merge rules are modeled in policy only."
                    .to_string(),
            ),
            UserMemorySyncLane::Diary => notes.push(
                "Diary bundle events are not emitted yet; append-only handoff notes remain future work."
                    .to_string(),
            ),
            UserMemorySyncLane::ConversationSummaries => notes.push(
                "Conversation-summary bundle events are not emitted yet; raw transcripts remain excluded by default."
                    .to_string(),
            ),
            UserMemorySyncLane::TemporalKg => notes.push(
                "Temporal-KG bundle events are not emitted yet; graph delta export remains future work."
                    .to_string(),
            ),
        }
    }
    Ok(events)
}

fn append_profile_bundle_events(
    state: &AppState,
    device_id: &str,
    payload_encryption_key: Option<&UserMemorySyncPayloadEncryptionKey>,
    events: &mut Vec<UserMemorySyncEvent>,
    notes: &mut Vec<String>,
) -> Result<()> {
    let Some(profile_state) = state.profile_state.as_ref() else {
        notes.push("Profile memory source is unavailable; no profile events emitted.".to_string());
        return Ok(());
    };
    let agents = profile_state.manager.list_agents()?;
    for agent in agents {
        let object_id = format!("agent:{}", agent.id);
        let payload_for_hash = json!({
            "schema_version": USER_MEMORY_SYNC_SCHEMA_VERSION,
            "kind": "profile_agent",
            "id": agent.id.as_str(),
            "role": agent.role.as_str(),
            "created_at": agent.created_at,
        });
        let mut payload_summary = BTreeMap::new();
        payload_summary.insert("role".to_string(), json!(agent.role.as_str()));
        payload_summary.insert("created_at".to_string(), json!(agent.created_at));
        events.push(build_bundle_event(
            UserMemorySyncLane::ProfileMemory,
            UserMemorySyncOperation::Upsert,
            object_id,
            Some(agent.created_at.to_string()),
            UserMemorySyncSensitivity::Low,
            "profile_agent",
            payload_for_hash,
            payload_summary,
            payload_encryption_key,
            UserMemorySyncProvenance {
                source_device_id: device_id.to_string(),
                source_store: "profile_memory".to_string(),
                source_record_id: agent.id,
                repo_id: None,
            },
        )?);
    }

    let preferences = profile_state.manager.list_preferences(None)?;
    let mut sensitive_count = 0usize;
    for preference in preferences {
        let category = serde_json::to_value(&preference.category).unwrap_or(Value::Null);
        let sensitivity = classify_profile_preference_sensitivity(&preference.content);
        if sensitivity == UserMemorySyncSensitivity::Sensitive {
            sensitive_count += 1;
        }
        let payload_for_hash = json!({
            "schema_version": USER_MEMORY_SYNC_SCHEMA_VERSION,
            "kind": "profile_preference",
            "id": preference.id.as_str(),
            "agent_id": preference.agent_id.as_str(),
            "category": category.clone(),
            "content": preference.content.as_str(),
            "last_updated": preference.last_updated,
            "embedding_provider": preference.embedding_provider.as_deref(),
            "embedding_model": preference.embedding_model.as_deref(),
            "embedding_dim": preference.embedding_dim,
        });
        let mut payload_summary = BTreeMap::new();
        payload_summary.insert("agent_id".to_string(), json!(preference.agent_id.as_str()));
        payload_summary.insert("category".to_string(), category);
        payload_summary.insert("last_updated".to_string(), json!(preference.last_updated));
        payload_summary.insert("content_bytes".to_string(), json!(preference.content.len()));
        if let Some(provider) = preference.embedding_provider.as_ref() {
            payload_summary.insert("embedding_provider".to_string(), json!(provider));
        }
        if let Some(model) = preference.embedding_model.as_ref() {
            payload_summary.insert("embedding_model".to_string(), json!(model));
        }
        if let Some(dim) = preference.embedding_dim {
            payload_summary.insert("embedding_dim".to_string(), json!(dim));
        }
        events.push(build_bundle_event(
            UserMemorySyncLane::ProfileMemory,
            UserMemorySyncOperation::Upsert,
            preference.id.clone(),
            Some(preference.last_updated.to_string()),
            sensitivity,
            "profile_preference",
            payload_for_hash,
            payload_summary,
            payload_encryption_key,
            UserMemorySyncProvenance {
                source_device_id: device_id.to_string(),
                source_store: "profile_memory".to_string(),
                source_record_id: preference.id,
                repo_id: None,
            },
        )?);
    }
    if sensitive_count > 0 {
        notes.push(format!(
            "{sensitive_count} profile preference event(s) were labeled sensitive by keyword scan; dry-run still returns hashes only."
        ));
    }
    Ok(())
}

fn append_inventory_bundle_event(
    state: &AppState,
    lane: UserMemorySyncLane,
    configured_lanes: &BTreeSet<UserMemorySyncLane>,
    device_id: &str,
    payload_encryption_key: Option<&UserMemorySyncPayloadEncryptionKey>,
    events: &mut Vec<UserMemorySyncEvent>,
    notes: &mut Vec<String>,
) -> Result<()> {
    let summary = build_lane_dry_run_summary(state, lane, configured_lanes)?;
    if !summary.source_available {
        if let Some(reason) = summary.blocked_reason {
            notes.push(format!("{}: {reason}", lane.as_str()));
        }
        return Ok(());
    }
    let records = summary.records.clone();
    let payload_for_hash = json!({
        "schema_version": USER_MEMORY_SYNC_SCHEMA_VERSION,
        "kind": "lane_inventory",
        "lane": lane.as_str(),
        "records": records.clone(),
        "configured_for_upload": summary.configured_for_upload,
        "adapter_ready": summary.adapter_ready,
    });
    let mut payload_summary = summary_records_to_values(&records);
    payload_summary.insert("inventory_only".to_string(), json!(true));
    payload_summary.insert("adapter_ready".to_string(), json!(summary.adapter_ready));
    payload_summary.insert(
        "configured_for_upload".to_string(),
        json!(summary.configured_for_upload),
    );
    let payload_kind = format!("{}_inventory", lane.as_str());
    events.push(build_bundle_event(
        lane,
        UserMemorySyncOperation::Upsert,
        format!("{}:inventory", lane.as_str()),
        None,
        UserMemorySyncSensitivity::Normal,
        &payload_kind,
        payload_for_hash,
        payload_summary,
        payload_encryption_key,
        UserMemorySyncProvenance {
            source_device_id: device_id.to_string(),
            source_store: lane.as_str().to_string(),
            source_record_id: "inventory".to_string(),
            repo_id: None,
        },
    )?);
    notes.extend(
        summary
            .notes
            .into_iter()
            .map(|note| format!("{}: {note}", lane.as_str())),
    );
    Ok(())
}

fn build_bundle_event(
    lane: UserMemorySyncLane,
    operation: UserMemorySyncOperation,
    object_id: String,
    object_version: Option<String>,
    sensitivity: UserMemorySyncSensitivity,
    payload_kind: &str,
    payload_for_hash: Value,
    payload_summary: BTreeMap<String, Value>,
    payload_encryption_key: Option<&UserMemorySyncPayloadEncryptionKey>,
    provenance: UserMemorySyncProvenance,
) -> Result<UserMemorySyncEvent> {
    let content_hash = stable_content_hash(&payload_for_hash)?;
    let event_id = stable_event_id(
        lane,
        operation,
        &object_id,
        object_version.as_deref(),
        &content_hash,
    );
    let payload_envelope = payload_encryption_key
        .map(|key| {
            encrypt_user_memory_sync_payload_envelope(
                key,
                lane,
                operation,
                &object_id,
                object_version.as_deref(),
                payload_kind,
                &payload_for_hash,
            )
        })
        .transpose()?;
    Ok(UserMemorySyncEvent {
        event_id,
        lane,
        operation,
        object_id,
        object_version,
        content_hash,
        sensitivity,
        payload_kind: payload_kind.to_string(),
        payload_summary,
        payload_envelope,
        provenance,
    })
}

fn summary_records_to_values(records: &BTreeMap<String, usize>) -> BTreeMap<String, Value> {
    records
        .iter()
        .map(|(key, value)| (key.clone(), json!(value)))
        .collect()
}

fn classify_profile_preference_sensitivity(content: &str) -> UserMemorySyncSensitivity {
    let lower = content.to_ascii_lowercase();
    let sensitive_terms = [
        "api key",
        "api_key",
        "secret",
        "token",
        "password",
        "credential",
        "private key",
        "access key",
    ];
    if sensitive_terms.iter().any(|term| lower.contains(term)) {
        UserMemorySyncSensitivity::Sensitive
    } else {
        UserMemorySyncSensitivity::Normal
    }
}

fn build_lane_dry_run_summary(
    state: &AppState,
    lane: UserMemorySyncLane,
    configured_lanes: &BTreeSet<UserMemorySyncLane>,
) -> Result<UserMemorySyncLaneDryRunSummary> {
    let policy = user_memory_sync_lane_policy(lane);
    let mut summary = UserMemorySyncLaneDryRunSummary {
        lane,
        source_available: false,
        adapter_ready: matches!(
            lane,
            UserMemorySyncLane::ProfileMemory
                | UserMemorySyncLane::PersonalPreferences
                | UserMemorySyncLane::MindClone
                | UserMemorySyncLane::GeneratedSkills
        ),
        configured_for_upload: state.user_memory_sync.enabled && configured_lanes.contains(&lane),
        records: BTreeMap::new(),
        estimated_payload_bytes: None,
        sensitive_exclusions: policy
            .sensitive_exclusions
            .into_iter()
            .map(ToOwned::to_owned)
            .collect(),
        blocked_reason: None,
        notes: Vec::new(),
    };
    match lane {
        UserMemorySyncLane::ProfileMemory => summarize_profile_memory(state, &mut summary)?,
        UserMemorySyncLane::PersonalPreferences => {
            summarize_personal_preferences(state, &mut summary)?
        }
        UserMemorySyncLane::MindClone => summarize_mind_clone(state, &mut summary)?,
        UserMemorySyncLane::GeneratedSkills => summarize_generated_skills(state, &mut summary)?,
        UserMemorySyncLane::RepoMemory => {
            summary.source_available = state.memory.is_some();
            summary.blocked_reason =
                Some("repo-memory delta adapter is not implemented in this slice".to_string());
        }
        UserMemorySyncLane::Diary => {
            summary.source_available = state.conversations.is_some();
            summary.blocked_reason =
                Some("diary sync adapter is not implemented in this slice".to_string());
        }
        UserMemorySyncLane::ConversationSummaries => {
            summary.source_available = state.conversations.is_some();
            summary.blocked_reason = Some(
                "conversation-summary sync adapter is not implemented in this slice".to_string(),
            );
        }
        UserMemorySyncLane::TemporalKg => {
            summary.source_available = state.conversations.is_some();
            summary.blocked_reason =
                Some("temporal-KG sync adapter is not implemented in this slice".to_string());
        }
    }
    if !summary.adapter_ready {
        summary.notes.push(
            "Lane policy is modeled now; push/pull adapter work remains a future slice."
                .to_string(),
        );
    }
    Ok(summary)
}

fn summarize_profile_memory(
    state: &AppState,
    summary: &mut UserMemorySyncLaneDryRunSummary,
) -> Result<()> {
    let Some(profile_state) = state.profile_state.as_ref() else {
        summary.blocked_reason = Some("profile memory is disabled".to_string());
        return Ok(());
    };
    summary.source_available = true;
    let agents = profile_state.manager.list_agents()?;
    let preferences = profile_state.manager.list_preferences(None)?;
    summary.records.insert("agents".to_string(), agents.len());
    summary
        .records
        .insert("preferences".to_string(), preferences.len());
    let agent_bytes = agents
        .iter()
        .map(|agent| agent.id.len() + agent.role.len() + 16)
        .sum::<usize>();
    let preference_bytes = preferences
        .iter()
        .map(|pref| pref.id.len() + pref.agent_id.len() + pref.content.len() + 64)
        .sum::<usize>();
    summary.estimated_payload_bytes = Some(agent_bytes + preference_bytes);
    summary.notes.push(
        "Counts preferences and agents only; preference content is not returned.".to_string(),
    );
    Ok(())
}

fn summarize_personal_preferences(
    state: &AppState,
    summary: &mut UserMemorySyncLaneDryRunSummary,
) -> Result<()> {
    let Some(personal_preferences) = state.personal_preferences.as_ref() else {
        summary.blocked_reason = Some("personal preferences memory is disabled".to_string());
        return Ok(());
    };
    summary.source_available = true;
    let status = personal_preferences.store.status()?;
    summary
        .records
        .insert("captures".to_string(), status.captures_total);
    summary
        .records
        .insert("derived_records".to_string(), status.derived_records_total);
    summary
        .records
        .insert("claims".to_string(), status.claims_total);
    summary
        .records
        .insert("feedback_events".to_string(), status.feedback_events_total);
    summary
        .records
        .insert("claim_evidence".to_string(), status.claim_evidence_total);
    summary
        .records
        .insert("claim_links".to_string(), status.claim_links_total);
    summary
        .records
        .insert("override_rules".to_string(), status.override_rules_total);
    summary
        .records
        .insert("redaction_spans".to_string(), status.redaction_spans_total);
    summary.records.insert(
        "retention_policies".to_string(),
        status.retention_policies_total,
    );
    summary.notes.push(
        "Raw transcript archives and export files are counted as local exclusions, not sync payloads."
            .to_string(),
    );
    summary.records.insert(
        "local_archive_files_excluded".to_string(),
        status.archive_files_total,
    );
    summary.records.insert(
        "local_export_files_excluded".to_string(),
        status.export_files_total,
    );
    Ok(())
}

fn summarize_mind_clone(
    state: &AppState,
    summary: &mut UserMemorySyncLaneDryRunSummary,
) -> Result<()> {
    let Some(personal_preferences) = state.personal_preferences.as_ref() else {
        summary.blocked_reason =
            Some("mind-clone data source is disabled with personal preferences".to_string());
        return Ok(());
    };
    summary.source_available = true;
    let status = personal_preferences.store.status()?;
    summary.records.insert(
        "identity_snapshots".to_string(),
        status.identity_snapshots_total,
    );
    summary.records.insert(
        "decision_patterns".to_string(),
        status.decision_patterns_total,
    );
    summary
        .records
        .insert("style_signals".to_string(), status.style_signals_total);
    summary
        .records
        .insert("clone_profiles".to_string(), status.clone_profiles_total);
    summary.records.insert(
        "clone_context_packs".to_string(),
        status.clone_context_packs_total,
    );
    summary.records.insert(
        "clone_evaluations".to_string(),
        status.clone_evaluations_total,
    );
    summary.records.insert(
        "project_timelines".to_string(),
        status.project_timelines_total,
    );
    summary
        .records
        .insert("goal_graph".to_string(), status.goal_graph_total);
    summary.records.insert(
        "operator_routines".to_string(),
        status.operator_routines_total,
    );
    summary
        .records
        .insert("operator_events".to_string(), status.operator_events_total);
    summary.records.insert(
        "clone_readiness_score_basis_points".to_string(),
        (status.clone_readiness.score.max(0.0) * 10_000.0).round() as usize,
    );
    summary.notes.push(
        "Mind-clone sync is inventory-only here; future push must preserve review and sensitivity labels."
            .to_string(),
    );
    Ok(())
}

fn summarize_generated_skills(
    state: &AppState,
    summary: &mut UserMemorySyncLaneDryRunSummary,
) -> Result<()> {
    let Some(personal_preferences) = state.personal_preferences.as_ref() else {
        summary.blocked_reason =
            Some("generated-skill data source is disabled with personal preferences".to_string());
        return Ok(());
    };
    summary.source_available = true;
    let status = personal_preferences.store.ai_terminal_status()?;
    summary.records.insert(
        "generated_skills".to_string(),
        status.generated_skills_total,
    );
    summary.records.insert(
        "installed_skills".to_string(),
        status.installed_skills_total,
    );
    summary
        .records
        .insert("review_required".to_string(), status.review_required_total);
    summary
        .records
        .insert("quarantined".to_string(), status.quarantined_total);
    summary.records.insert(
        "activation_events".to_string(),
        status.activation_events_total,
    );
    summary.records.insert(
        "accepted_activation_events".to_string(),
        status.accepted_activation_events_total,
    );
    summary.records.insert(
        "rejected_activation_events".to_string(),
        status.rejected_activation_events_total,
    );
    summary.records.insert(
        "stale_generated_skills".to_string(),
        status.stale_generated_skills_total,
    );
    summary.records.insert(
        "replay_validations".to_string(),
        status.generated_skill_replay_validations_total,
    );
    summary.notes.push(
        "Remote generated skills must be staged for local review and must never auto-install from down-sync."
            .to_string(),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthMethod, PrincipalStatus};

    fn auth_context(principal_id: &str, credential_fingerprint: &str) -> AuthContext {
        AuthContext {
            auth_method: AuthMethod::ExternalApiKeyIntrospection,
            issuer: "mswarm".to_string(),
            subject: Some(principal_id.to_string()),
            credential_id: format!("cred-{credential_fingerprint}"),
            principal_id: principal_id.to_string(),
            scopes: vec!["docdex:user_memory:sync".to_string()],
            status: PrincipalStatus::Active,
            expires_at_ms: None,
            credential_fingerprint: credential_fingerprint.to_string(),
            claims_json: None,
        }
    }

    #[test]
    fn auth_principal_key_merges_credentials_for_same_user() {
        let first = auth_context("user-1", "fingerprint-a");
        let second = auth_context("user-1", "fingerprint-b");
        let other = auth_context("user-2", "fingerprint-a");

        assert_eq!(
            auth_context_user_memory_sync_principal_key(&first),
            auth_context_user_memory_sync_principal_key(&second)
        );
        assert_ne!(
            auth_context_user_memory_sync_principal_key(&first),
            auth_context_user_memory_sync_principal_key(&other)
        );
    }

    #[test]
    fn auth_identity_does_not_expose_raw_credential() {
        let ctx = auth_context("user-1", "fingerprint-a");
        let identity = auth_context_user_memory_sync_identity(&ctx);

        assert!(identity.configured);
        assert_eq!(
            identity.credential_fingerprint.as_deref(),
            Some("fingerprint-a")
        );
        assert!(!identity.raw_credential_returned);
        assert!(identity.source.contains("mswarm"));
    }
}
