use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use chrono::{Datelike, Utc};
use flate2::write::GzEncoder;
use flate2::Compression;
use hmac::{Hmac, Mac};
use reqwest::Client;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;

use crate::config::{self, AppConfig};
use crate::mcoda::registry::default_db_path;
use crate::mswarm;
use crate::orchestrator::web::{WebDiscoveryStatus, WebFetchResult};
use crate::setup::config::{set_mswarm_telemetry_config, MswarmTelemetryUpdate};
use crate::state_layout::{ensure_state_dir_secure, StateLayout};
use crate::{delegation_telemetry, metrics::DelegationTelemetrySnapshot};

const EVENT_SCHEMA_VERSION: u32 = 1;
const PACKAGE_SCHEMA_VERSION: u32 = 1;
const PACKAGE_RETENTION_DAYS: i64 = 30;
const UPLOAD_RETRY_ATTEMPTS: u32 = 3;
const UPLOAD_RETRY_BASE_MS: u64 = 1_000;
const DOCDEX_PACKAGE_INGEST_PATH: &str = "/v1/swarm/docdex/packages/ingest";

type HmacSha256 = Hmac<sha2::Sha256>;

#[derive(Debug, Serialize, Deserialize)]
struct TelemetryEnvelope<T> {
    schema_version: u32,
    event_id: String,
    event_type: String,
    created_at_ms: u128,
    payload: T,
}

#[derive(Debug, Serialize, Deserialize)]
struct WebSearchPayload {
    query: String,
    repo_root: Option<String>,
    context: Option<String>,
    status: String,
    reason: Option<String>,
    provider: Option<String>,
    result_count: usize,
    results: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WebFetchPayload {
    query: Option<String>,
    repo_root: Option<String>,
    context: Option<String>,
    provider: Option<String>,
    url: String,
    status: Option<u16>,
    fetched_at_epoch_ms: Option<u128>,
    cached: bool,
    content: Option<String>,
    ai_digested_content: Option<String>,
    ai_digested_kind: Option<String>,
    relevance_score: Option<f32>,
    error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WebAnswerPayload {
    query: Option<String>,
    repo_root: Option<String>,
    context: Option<String>,
    provider: Option<String>,
    url: String,
    fetched_at_epoch_ms: Option<u128>,
    cached: bool,
    ai_digested_kind: Option<String>,
    ai_digested_content: String,
    relevance_score: Option<f32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DelegationFailurePayload {
    ts: String,
    source: Option<String>,
    kind: String,
    task_type: String,
    mode: String,
    repo_id: Option<String>,
    repo_root: Option<String>,
    local_target: String,
    attempt: usize,
    recovery_action: String,
    error: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DelegationSavingsProjectPayload {
    project: String,
    state_key: String,
    delegate_requests_total: u64,
    delegate_offloaded_total: u64,
    delegate_fallbacks_total: u64,
    delegate_failed_total: u64,
    delegate_token_estimate_total: u64,
    delegate_local_tokens_total: u64,
    delegate_primary_tokens_total: u64,
    delegate_tokens_total: u64,
    delegate_token_savings_total: u64,
    delegate_local_cost_micros_total: u64,
    delegate_primary_cost_micros_total: u64,
    delegate_avoided_primary_cost_micros_total: u64,
    delegate_cost_savings_micros_total: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct DelegationSavingsPayload {
    generated_at_ms: u128,
    delegate_requests_total: u64,
    delegate_offloaded_total: u64,
    delegate_fallbacks_total: u64,
    delegate_failed_total: u64,
    delegate_token_estimate_total: u64,
    delegate_local_tokens_total: u64,
    delegate_primary_tokens_total: u64,
    delegate_tokens_total: u64,
    delegate_token_savings_total: u64,
    delegate_local_cost_micros_total: u64,
    delegate_primary_cost_micros_total: u64,
    delegate_avoided_primary_cost_micros_total: u64,
    delegate_cost_savings_micros_total: u64,
    configured_primary_usd_per_million_tokens: f64,
    configured_local_usd_per_million_tokens: f64,
    effective_avoided_primary_usd_per_million_tokens: Option<f64>,
    effective_local_usd_per_million_tokens: Option<f64>,
    project_count: usize,
    projects: Vec<DelegationSavingsProjectPayload>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HousekeepingSummary {
    pub exported_ratings: usize,
    pub exported_delegation_snapshots: usize,
    pub created_packages: usize,
    pub uploaded_packages: usize,
    pub failed_packages: usize,
    pub pruned_paths: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct PendingPackageMetadata {
    package_id: String,
    schema_version: u32,
    created_at_ms: u128,
    product: String,
    product_version: String,
    client_id: String,
    client_type: String,
    consent_policy_version: String,
    payload_file_name: String,
    checksum_sha256: String,
    signature_base64: String,
    event_count: usize,
    rating_count: usize,
    upload_attempts: u32,
    last_error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct UploadPackage {
    schema_version: u32,
    package_id: String,
    created_at_ms: u128,
    product: String,
    product_version: String,
    client_id: String,
    client_type: String,
    consent_policy_version: String,
    events: Vec<Value>,
    ratings: Vec<Value>,
}

#[derive(Debug, Clone)]
struct UploadAuth {
    base_url: String,
    api_key: Option<String>,
    consent_token: String,
    client_id: String,
    client_type: String,
    consent_policy_version: String,
    signing_secret: String,
}

#[derive(Debug, Deserialize)]
struct PackageIngestResponse {
    accepted: bool,
}

pub fn resolve_state_layout(global_state_dir: Option<&Path>) -> Result<StateLayout> {
    let base_dir = global_state_dir
        .map(Path::to_path_buf)
        .or_else(|| {
            std::env::var("DOCDEX_STATE_DIR").ok().and_then(|value| {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(trimmed))
                }
            })
        })
        .or_else(|| crate::state_paths::default_state_base_dir().ok())
        .ok_or_else(|| anyhow!("resolve mswarm telemetry state dir"))?;
    let layout = StateLayout::new(base_dir);
    layout.ensure_global_dirs()?;
    Ok(layout)
}

pub fn record_web_research(
    global_state_dir: Option<&Path>,
    repo_root: Option<&Path>,
    query: &str,
    query_context: Option<&str>,
    status: &WebDiscoveryStatus,
) -> Result<()> {
    let layout = resolve_state_layout(global_state_dir)?;
    let repo_root = normalize_repo_root(repo_root);
    let provider = status
        .discovery
        .as_ref()
        .map(|value| value.provider.clone());
    let results = status
        .discovery
        .as_ref()
        .map(|value| {
            value
                .results
                .iter()
                .map(|item| item.url.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    write_event(
        &layout,
        "web_search",
        &WebSearchPayload {
            query: query.to_string(),
            repo_root: repo_root.clone(),
            context: query_context.map(str::to_string),
            status: web_discovery_status_code(status),
            reason: status.reason.clone(),
            provider: provider.clone(),
            result_count: results.len(),
            results,
        },
    )?;

    if let Some(fetches) = status.fetches.as_ref() {
        for fetch in fetches {
            record_fetch_event(
                &layout,
                repo_root.as_deref(),
                query_context,
                provider.as_deref(),
                Some(query),
                fetch,
            )?;
        }
    }

    Ok(())
}

pub fn record_direct_web_fetch(
    global_state_dir: Option<&Path>,
    repo_root: Option<&Path>,
    fetch: &WebFetchResult,
) -> Result<()> {
    let layout = resolve_state_layout(global_state_dir)?;
    record_fetch_event(
        &layout,
        normalize_repo_root(repo_root).as_deref(),
        None,
        None,
        None,
        fetch,
    )
}

pub fn record_delegation_failure(
    global_state_dir: Option<&Path>,
    ts: &str,
    source: Option<&str>,
    kind: &str,
    task_type: &str,
    mode: &str,
    repo_id: Option<&str>,
    repo_root: Option<&str>,
    local_target: &str,
    attempt: usize,
    recovery_action: &str,
    error: &str,
) -> Result<()> {
    let layout = resolve_state_layout(global_state_dir)?;
    write_event(
        &layout,
        "delegation_failure",
        &DelegationFailurePayload {
            ts: ts.to_string(),
            source: source.map(str::to_string),
            kind: kind.to_string(),
            task_type: task_type.to_string(),
            mode: mode.to_string(),
            repo_id: repo_id.map(str::to_string),
            repo_root: repo_root.map(str::to_string),
            local_target: local_target.to_string(),
            attempt,
            recovery_action: recovery_action.to_string(),
            error: error.to_string(),
        },
    )?;
    Ok(())
}

pub fn run_housekeeping_cycle(global_state_dir: Option<&Path>) -> Result<HousekeepingSummary> {
    crate::mswarm::block_on_http_future(run_housekeeping_cycle_async(
        global_state_dir.map(Path::to_path_buf),
    ))
}

pub async fn run_housekeeping_cycle_async(
    global_state_dir: Option<PathBuf>,
) -> Result<HousekeepingSummary> {
    let mut summary = HousekeepingSummary::default();
    let config_path = config::default_config_path().context("resolve docdex config path")?;
    let app_config = config::load_config_from_path(&config_path)
        .with_context(|| format!("load {}", config_path.display()))?;
    let telemetry = &app_config.integrations.mswarm.telemetry;
    if !telemetry.required || !telemetry.consent_accepted {
        return Ok(summary);
    }
    if telemetry.client_id.trim().is_empty()
        || telemetry
            .consent_token
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
    {
        return Ok(summary);
    }

    let layout = resolve_state_layout(
        global_state_dir
            .as_deref()
            .or(app_config.core.global_state_dir.as_deref()),
    )?;
    summary.pruned_paths = prune_stale_artifacts(&layout)?;
    summary.exported_ratings = export_mcoda_ratings_to_spool(&layout)?;
    summary.exported_delegation_snapshots =
        export_delegation_savings_to_spool(&layout, &app_config)?;
    if let Some(auth) = resolve_upload_auth(&config_path, &app_config).await? {
        if create_pending_package(&layout, &auth)?.is_some() {
            summary.created_packages += 1;
        }
        let upload_result = upload_queued_packages_async(&layout, &auth).await?;
        summary.uploaded_packages = upload_result.uploaded;
        summary.failed_packages = upload_result.failed;
        if upload_result.updated_last_upload_at_ms > 0 {
            let _ = set_mswarm_telemetry_config(MswarmTelemetryUpdate {
                required: None,
                consent_accepted: None,
                consent_policy_version: None,
                consent_token: None,
                client_id: None,
                client_type: None,
                registered_at_ms: None,
                last_upload_at_ms: Some(upload_result.updated_last_upload_at_ms),
                upload_signing_secret: None,
            });
        }
    }
    Ok(summary)
}

async fn resolve_upload_auth(
    _config_path: &Path,
    app_config: &AppConfig,
) -> Result<Option<UploadAuth>> {
    let telemetry = &app_config.integrations.mswarm.telemetry;
    let consent_token = telemetry
        .consent_token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let Some(consent_token) = consent_token else {
        return Ok(None);
    };
    let client_id = telemetry.client_id.trim();
    if client_id.is_empty() {
        return Ok(None);
    }
    let client_type = telemetry.client_type.trim();
    let policy_version = mswarm::effective_policy_version(Some(&telemetry.consent_policy_version));
    let api_key = app_config
        .integrations
        .mswarm
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let signing_secret = if let Some(api_key) = api_key.clone() {
        api_key
    } else if let Some(existing) = app_config
        .integrations
        .mswarm
        .telemetry
        .upload_signing_secret
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
    {
        existing
    } else {
        let response = mswarm::register_free_docdex_client_async(
            &app_config.integrations.mswarm.base_url,
            Some(client_id),
            &policy_version,
            now_epoch_ms(),
        )
        .await?;
        let secret = response
            .upload_signing_secret
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                anyhow!("mswarm free-client registration did not return upload signing secret")
            })?;
        let _ = set_mswarm_telemetry_config(MswarmTelemetryUpdate {
            required: None,
            consent_accepted: None,
            consent_policy_version: Some(policy_version.clone()),
            consent_token: Some(response.consent_token),
            client_id: Some(client_id.to_string()),
            client_type: Some(
                response
                    .client_type
                    .unwrap_or_else(|| mswarm::DOCDEX_FREE_CLIENT_TYPE.to_string()),
            ),
            registered_at_ms: None,
            last_upload_at_ms: None,
            upload_signing_secret: Some(secret.clone()),
        });
        secret
    };

    Ok(Some(UploadAuth {
        base_url: app_config.integrations.mswarm.base_url.clone(),
        api_key,
        consent_token,
        client_id: client_id.to_string(),
        client_type: if client_type.is_empty() {
            mswarm::DOCDEX_FREE_CLIENT_TYPE.to_string()
        } else {
            client_type.to_string()
        },
        consent_policy_version: policy_version,
        signing_secret,
    }))
}

fn export_mcoda_ratings_to_spool(layout: &StateLayout) -> Result<usize> {
    let db_path = default_db_path()?;
    if !db_path.exists() {
        return Ok(0);
    }
    let conn = Connection::open(&db_path)
        .with_context(|| format!("open mcoda db {}", db_path.display()))?;
    if !sqlite_table_exists(&conn, "agent_run_ratings")? {
        return Ok(0);
    }

    let agent_columns = sqlite_table_columns(&conn, "agents")?;
    let sql = "SELECT id, agent_id, command_name, discipline, complexity, quality_score, tokens_total, duration_seconds, iterations, total_cost, run_score, rating_version, raw_review_json, created_at FROM agent_run_ratings ORDER BY created_at ASC";
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map([], |row| {
        let raw_review_json: Option<String> = row.get(12)?;
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, f64>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, f64>(7)?,
            row.get::<_, i64>(8)?,
            row.get::<_, f64>(9)?,
            row.get::<_, f64>(10)?,
            row.get::<_, String>(11)?,
            raw_review_json,
            row.get::<_, String>(13)?,
        ))
    })?;

    let mut exported = 0usize;
    for row in rows {
        let (
            run_id,
            agent_id,
            command_name,
            discipline,
            complexity,
            quality_score,
            tokens_total,
            duration_seconds,
            iterations,
            total_cost,
            run_score,
            rating_version,
            raw_review_json,
            created_at,
        ) = row?;
        let created_at_ms = parse_rfc3339_epoch_ms(&created_at).unwrap_or_else(now_epoch_ms);
        let day_dir = layout
            .mswarm_ratings_dir()
            .join(event_day_bucket(created_at_ms));
        ensure_state_dir_secure(&day_dir)?;
        let path = day_dir.join(format!("{run_id}.json"));
        if path.exists() {
            continue;
        }
        let agent_snapshot = load_mcoda_agent_snapshot(&conn, &agent_id, &agent_columns)?;
        let raw_review_json = raw_review_json
            .as_deref()
            .and_then(|value| serde_json::from_str::<Value>(value).ok());
        let envelope = json!({
            "schema_version": EVENT_SCHEMA_VERSION,
            "event_id": run_id,
            "event_type": "mcoda_agent_rating",
            "created_at_ms": created_at_ms,
            "payload": {
                "agent_id": agent_id,
                "command_name": command_name,
                "discipline": discipline,
                "complexity": complexity,
                "quality_score": quality_score,
                "tokens_total": tokens_total,
                "duration_seconds": duration_seconds,
                "iterations": iterations,
                "total_cost": total_cost,
                "run_score": run_score,
                "rating_version": rating_version,
                "created_at": created_at,
                "raw_review_json": raw_review_json,
                "agent_snapshot": agent_snapshot,
            }
        });
        fs::write(&path, serde_json::to_vec_pretty(&envelope)?)?;
        exported += 1;
    }

    Ok(exported)
}

fn load_mcoda_agent_snapshot(
    conn: &Connection,
    agent_id: &str,
    columns: &std::collections::HashSet<String>,
) -> Result<Option<Value>> {
    if columns.is_empty() {
        return Ok(None);
    }
    let rating_sql = if columns.contains("rating") {
        "rating"
    } else {
        "NULL"
    };
    let reasoning_sql = if columns.contains("reasoning_rating") {
        "reasoning_rating"
    } else {
        "NULL"
    };
    let samples_sql = if columns.contains("rating_samples") {
        "rating_samples"
    } else {
        "NULL"
    };
    let max_complexity_sql = if columns.contains("max_complexity") {
        "max_complexity"
    } else {
        "NULL"
    };
    let health_sql = if columns.contains("health_status") {
        "health_status"
    } else {
        "NULL"
    };
    let default_model_sql = if columns.contains("default_model") {
        "default_model"
    } else {
        "NULL"
    };
    let adapter_sql = if columns.contains("adapter") {
        "adapter"
    } else {
        "NULL"
    };
    let sql = format!(
        "SELECT {rating_sql}, {reasoning_sql}, {samples_sql}, {max_complexity_sql}, {health_sql}, {default_model_sql}, {adapter_sql} FROM agents WHERE id = ?1 LIMIT 1"
    );
    let snapshot = conn
        .query_row(&sql, params![agent_id], |row| {
            Ok(json!({
                "rating": row.get::<_, Option<f64>>(0)?,
                "reasoning_rating": row.get::<_, Option<f64>>(1)?,
                "rating_samples": row.get::<_, Option<i64>>(2)?,
                "max_complexity": row.get::<_, Option<i64>>(3)?,
                "health_status": row.get::<_, Option<String>>(4)?,
                "default_model": row.get::<_, Option<String>>(5)?,
                "adapter": row.get::<_, Option<String>>(6)?,
            }))
        })
        .optional()?;
    Ok(snapshot)
}

fn export_delegation_savings_to_spool(
    layout: &StateLayout,
    app_config: &AppConfig,
) -> Result<usize> {
    let repo_snapshots = delegation_telemetry::load_repo_snapshots(layout.base_dir())?;
    let projects = repo_snapshots
        .into_iter()
        .filter(|project| !project.snapshot.is_zero())
        .map(build_delegation_project_payload)
        .collect::<Vec<_>>();

    let aggregate_from_projects = aggregate_project_snapshots(&projects);
    let global_snapshot = delegation_telemetry::load_global_snapshot(layout.base_dir())?
        .filter(|snapshot| !snapshot.is_zero())
        .unwrap_or_else(|| aggregate_from_projects.clone());
    if global_snapshot.is_zero() && projects.is_empty() {
        return Ok(0);
    }

    write_event(
        layout,
        "delegation_savings_snapshot",
        &DelegationSavingsPayload {
            generated_at_ms: now_epoch_ms(),
            delegate_requests_total: global_snapshot.delegate_requests_total,
            delegate_offloaded_total: global_snapshot.delegate_offloaded_total,
            delegate_fallbacks_total: global_snapshot.delegate_fallbacks_total,
            delegate_failed_total: global_snapshot.delegate_failed_total,
            delegate_token_estimate_total: global_snapshot.delegate_token_estimate_total,
            delegate_local_tokens_total: global_snapshot.delegate_local_tokens_total,
            delegate_primary_tokens_total: global_snapshot.delegate_primary_tokens_total,
            delegate_tokens_total: global_snapshot
                .delegate_local_tokens_total
                .saturating_add(global_snapshot.delegate_primary_tokens_total),
            delegate_token_savings_total: global_snapshot.delegate_token_savings_total,
            delegate_local_cost_micros_total: global_snapshot.delegate_local_cost_micros_total,
            delegate_primary_cost_micros_total: global_snapshot.delegate_primary_cost_micros_total,
            delegate_avoided_primary_cost_micros_total: global_snapshot
                .avoided_primary_cost_micros_total(),
            delegate_cost_savings_micros_total: global_snapshot.delegate_cost_savings_micros_total,
            configured_primary_usd_per_million_tokens: app_config
                .llm
                .delegation
                .primary_usd_per_million_tokens,
            configured_local_usd_per_million_tokens: app_config
                .llm
                .delegation
                .local_usd_per_million_tokens,
            effective_avoided_primary_usd_per_million_tokens: global_snapshot
                .effective_avoided_primary_usd_per_million_tokens(),
            effective_local_usd_per_million_tokens: effective_cost_per_million(
                global_snapshot.delegate_local_cost_micros_total,
                global_snapshot.delegate_local_tokens_total,
            ),
            project_count: projects.len(),
            projects,
        },
    )?;

    Ok(1)
}

fn build_delegation_project_payload(
    project: delegation_telemetry::RepoDelegationTelemetrySnapshot,
) -> DelegationSavingsProjectPayload {
    DelegationSavingsProjectPayload {
        project: project.project,
        state_key: project.state_key,
        delegate_requests_total: project.snapshot.delegate_requests_total,
        delegate_offloaded_total: project.snapshot.delegate_offloaded_total,
        delegate_fallbacks_total: project.snapshot.delegate_fallbacks_total,
        delegate_failed_total: project.snapshot.delegate_failed_total,
        delegate_token_estimate_total: project.snapshot.delegate_token_estimate_total,
        delegate_local_tokens_total: project.snapshot.delegate_local_tokens_total,
        delegate_primary_tokens_total: project.snapshot.delegate_primary_tokens_total,
        delegate_tokens_total: project
            .snapshot
            .delegate_local_tokens_total
            .saturating_add(project.snapshot.delegate_primary_tokens_total),
        delegate_token_savings_total: project.snapshot.delegate_token_savings_total,
        delegate_local_cost_micros_total: project.snapshot.delegate_local_cost_micros_total,
        delegate_primary_cost_micros_total: project.snapshot.delegate_primary_cost_micros_total,
        delegate_avoided_primary_cost_micros_total: project
            .snapshot
            .avoided_primary_cost_micros_total(),
        delegate_cost_savings_micros_total: project.snapshot.delegate_cost_savings_micros_total,
    }
}

fn aggregate_project_snapshots(
    projects: &[DelegationSavingsProjectPayload],
) -> DelegationTelemetrySnapshot {
    let mut aggregate = DelegationTelemetrySnapshot::default();
    for project in projects {
        aggregate.merge(DelegationTelemetrySnapshot {
            delegate_requests_total: project.delegate_requests_total,
            delegate_offloaded_total: project.delegate_offloaded_total,
            delegate_fallbacks_total: project.delegate_fallbacks_total,
            delegate_failed_total: project.delegate_failed_total,
            delegate_token_estimate_total: project.delegate_token_estimate_total,
            delegate_local_tokens_total: project.delegate_local_tokens_total,
            delegate_primary_tokens_total: project.delegate_primary_tokens_total,
            delegate_token_savings_total: project.delegate_token_savings_total,
            delegate_local_cost_micros_total: project.delegate_local_cost_micros_total,
            delegate_primary_cost_micros_total: project.delegate_primary_cost_micros_total,
            delegate_cost_savings_micros_total: project.delegate_cost_savings_micros_total,
        });
    }
    aggregate
}

fn effective_cost_per_million(cost_micros: u64, tokens: u64) -> Option<f64> {
    if tokens == 0 {
        None
    } else {
        Some(cost_micros as f64 / tokens as f64)
    }
}

fn create_pending_package(
    layout: &StateLayout,
    auth: &UploadAuth,
) -> Result<Option<PendingPackageMetadata>> {
    let event_files = collect_json_files(&layout.mswarm_events_dir())?;
    let rating_files = collect_json_files(&layout.mswarm_ratings_dir())?;
    if event_files.is_empty() && rating_files.is_empty() {
        return Ok(None);
    }
    let events = read_json_files(&event_files)?;
    let ratings = read_json_files(&rating_files)?;
    let created_at_ms = now_epoch_ms();
    let package_id = format!("docdex-telemetry-{}-{}", created_at_ms, Uuid::new_v4());
    let package = UploadPackage {
        schema_version: PACKAGE_SCHEMA_VERSION,
        package_id: package_id.clone(),
        created_at_ms,
        product: "docdex".to_string(),
        product_version: env!("CARGO_PKG_VERSION").to_string(),
        client_id: auth.client_id.clone(),
        client_type: auth.client_type.clone(),
        consent_policy_version: auth.consent_policy_version.clone(),
        events,
        ratings,
    };
    let payload_file_name = format!("{package_id}.json.gz");
    let payload_path = layout
        .mswarm_packages_pending_dir()
        .join(&payload_file_name);
    let payload_bytes = gzip_json(&package)?;
    let checksum_sha256 = sha256_hex(&payload_bytes);
    let signature_base64 = hmac_sign_base64(auth.signing_secret.as_bytes(), &payload_bytes)?;
    fs::write(&payload_path, &payload_bytes)
        .with_context(|| format!("write {}", payload_path.display()))?;
    let metadata = PendingPackageMetadata {
        package_id,
        schema_version: PACKAGE_SCHEMA_VERSION,
        created_at_ms,
        product: "docdex".to_string(),
        product_version: env!("CARGO_PKG_VERSION").to_string(),
        client_id: auth.client_id.clone(),
        client_type: auth.client_type.clone(),
        consent_policy_version: auth.consent_policy_version.clone(),
        payload_file_name,
        checksum_sha256,
        signature_base64,
        event_count: event_files.len(),
        rating_count: rating_files.len(),
        upload_attempts: 0,
        last_error: None,
    };
    let meta_path = metadata_path_for(&layout.mswarm_packages_pending_dir(), &metadata.package_id);
    fs::write(&meta_path, serde_json::to_vec_pretty(&metadata)?)
        .with_context(|| format!("write {}", meta_path.display()))?;
    remove_packaged_source_files(&event_files)?;
    remove_packaged_source_files(&rating_files)?;
    Ok(Some(metadata))
}

struct UploadBatchResult {
    uploaded: usize,
    failed: usize,
    updated_last_upload_at_ms: u64,
}

#[cfg_attr(not(test), allow(dead_code))]
fn upload_queued_packages(layout: &StateLayout, auth: &UploadAuth) -> Result<UploadBatchResult> {
    crate::mswarm::block_on_http_future(upload_queued_packages_async(layout, auth))
}

async fn upload_queued_packages_async(
    layout: &StateLayout,
    auth: &UploadAuth,
) -> Result<UploadBatchResult> {
    let mut result = UploadBatchResult {
        uploaded: 0,
        failed: 0,
        updated_last_upload_at_ms: 0,
    };
    let client = Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .context("build mswarm package upload client")?;
    let mut meta_paths = collect_package_metadata_paths(&layout.mswarm_packages_pending_dir())?;
    meta_paths.extend(collect_package_metadata_paths(
        &layout.mswarm_packages_failed_dir(),
    )?);
    meta_paths.sort();
    for meta_path in meta_paths {
        let current_dir = meta_path
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| anyhow!("resolve package metadata parent"))?;
        let mut metadata: PendingPackageMetadata = serde_json::from_slice(
            &fs::read(&meta_path).with_context(|| format!("read {}", meta_path.display()))?,
        )?;
        let payload_path = current_dir.join(&metadata.payload_file_name);
        let payload_bytes =
            fs::read(&payload_path).with_context(|| format!("read {}", payload_path.display()))?;
        let mut uploaded = false;
        let mut last_error = None;
        for _ in 0..UPLOAD_RETRY_ATTEMPTS {
            match upload_package(&client, auth, &metadata, &payload_bytes).await {
                Ok(()) => {
                    uploaded = true;
                    break;
                }
                Err(err) => {
                    last_error = Some(err.to_string());
                    std::thread::sleep(Duration::from_millis(UPLOAD_RETRY_BASE_MS));
                }
            }
        }
        if uploaded {
            let _ = fs::remove_file(&payload_path);
            let _ = fs::remove_file(&meta_path);
            result.uploaded += 1;
            result.updated_last_upload_at_ms = u64::try_from(now_epoch_ms()).unwrap_or(u64::MAX);
            continue;
        }
        metadata.upload_attempts = metadata
            .upload_attempts
            .saturating_add(UPLOAD_RETRY_ATTEMPTS);
        metadata.last_error = last_error;
        let failed_meta =
            metadata_path_for(&layout.mswarm_packages_failed_dir(), &metadata.package_id);
        let failed_payload = layout
            .mswarm_packages_failed_dir()
            .join(&metadata.payload_file_name);
        if current_dir != layout.mswarm_packages_failed_dir() {
            fs::rename(&payload_path, &failed_payload)
                .with_context(|| format!("move {} to failed", payload_path.display()))?;
        }
        fs::write(&failed_meta, serde_json::to_vec_pretty(&metadata)?)
            .with_context(|| format!("write {}", failed_meta.display()))?;
        if meta_path != failed_meta {
            let _ = fs::remove_file(&meta_path);
        }
        result.failed += 1;
    }
    Ok(result)
}

async fn upload_package(
    client: &Client,
    auth: &UploadAuth,
    metadata: &PendingPackageMetadata,
    payload_bytes: &[u8],
) -> Result<()> {
    let url = format!(
        "{}{}",
        auth.base_url.trim_end_matches('/'),
        DOCDEX_PACKAGE_INGEST_PATH
    );
    let mut request = client.post(url).json(&json!({
        "client_id": metadata.client_id,
        "client_type": metadata.client_type,
        "consent_token": auth.consent_token,
        "package_id": metadata.package_id,
        "created_at_ms": metadata.created_at_ms,
        "checksum_sha256": metadata.checksum_sha256,
        "signature_base64": metadata.signature_base64,
        "payload_encoding": "gzip+json",
        "payload_base64": base64::engine::general_purpose::STANDARD.encode(payload_bytes),
        "product": metadata.product,
        "product_version": metadata.product_version,
        "consent_policy_version": metadata.consent_policy_version,
    }));
    if let Some(api_key) = auth.api_key.as_deref() {
        request = request.header("x-api-key", api_key);
    }
    let response = request.send().await.context("upload mswarm package")?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!(
            "mswarm package upload failed with status {}: {}",
            status,
            body.trim()
        ));
    }
    let ingest: PackageIngestResponse = response
        .json()
        .await
        .context("decode mswarm package upload response")?;
    if !ingest.accepted {
        return Err(anyhow!("mswarm package upload was not accepted"));
    }
    Ok(())
}

fn prune_stale_artifacts(layout: &StateLayout) -> Result<usize> {
    let cutoff_ms =
        now_epoch_ms().saturating_sub((PACKAGE_RETENTION_DAYS as u128) * 24 * 60 * 60 * 1000);
    let mut pruned = 0usize;
    pruned += prune_bucketed_dirs(&layout.mswarm_events_dir(), cutoff_ms)?;
    pruned += prune_bucketed_dirs(&layout.mswarm_ratings_dir(), cutoff_ms)?;
    pruned += prune_package_dir(&layout.mswarm_packages_pending_dir(), cutoff_ms)?;
    pruned += prune_package_dir(&layout.mswarm_packages_failed_dir(), cutoff_ms)?;
    pruned += prune_package_dir(&layout.mswarm_packages_sent_dir(), cutoff_ms)?;
    Ok(pruned)
}

fn prune_bucketed_dirs(root: &Path, cutoff_ms: u128) -> Result<usize> {
    if !root.exists() {
        return Ok(0);
    }
    let cutoff_bucket = event_day_bucket(cutoff_ms);
    let mut removed = 0usize;
    for entry in fs::read_dir(root).with_context(|| format!("read {}", root.display()))? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        for day_entry in fs::read_dir(&path).with_context(|| format!("read {}", path.display()))? {
            let day_entry = day_entry?;
            let day_path = day_entry.path();
            if !day_path.is_dir() {
                continue;
            }
            let Some(day_name) = day_path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if day_name <= cutoff_bucket.as_str() {
                fs::remove_dir_all(&day_path)
                    .with_context(|| format!("remove {}", day_path.display()))?;
                removed += 1;
            }
        }
    }
    Ok(removed)
}

fn prune_package_dir(root: &Path, cutoff_ms: u128) -> Result<usize> {
    if !root.exists() {
        return Ok(0);
    }
    let mut removed = 0usize;
    for meta_path in collect_package_metadata_paths(root)? {
        let metadata: PendingPackageMetadata = serde_json::from_slice(
            &fs::read(&meta_path).with_context(|| format!("read {}", meta_path.display()))?,
        )?;
        if metadata.created_at_ms > cutoff_ms {
            continue;
        }
        let payload_path = root.join(&metadata.payload_file_name);
        let _ = fs::remove_file(&payload_path);
        let _ = fs::remove_file(&meta_path);
        removed += 1;
    }
    Ok(removed)
}

fn collect_package_metadata_paths(root: &Path) -> Result<Vec<PathBuf>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut paths = Vec::new();
    for entry in fs::read_dir(root).with_context(|| format!("read {}", root.display()))? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path
            .file_name()
            .and_then(|value| value.to_str())
            .map(|value| value.ends_with(".meta.json"))
            .unwrap_or(false)
        {
            paths.push(path);
        }
    }
    Ok(paths)
}

fn metadata_path_for(root: &Path, package_id: &str) -> PathBuf {
    root.join(format!("{package_id}.meta.json"))
}

fn collect_json_files(root: &Path) -> Result<Vec<PathBuf>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in fs::read_dir(&path).with_context(|| format!("read {}", path.display()))? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|value| value.to_str()) == Some("json") {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

fn read_json_files(paths: &[PathBuf]) -> Result<Vec<Value>> {
    let mut values = Vec::with_capacity(paths.len());
    for path in paths {
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        values.push(
            serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?,
        );
    }
    Ok(values)
}

fn remove_packaged_source_files(paths: &[PathBuf]) -> Result<()> {
    for path in paths {
        let _ = fs::remove_file(path);
        prune_empty_parent_dirs(path.parent());
    }
    Ok(())
}

fn prune_empty_parent_dirs(mut current: Option<&Path>) {
    while let Some(path) = current {
        let is_empty = fs::read_dir(path)
            .ok()
            .and_then(|mut entries| entries.next().transpose().ok())
            .flatten()
            .is_none();
        if !is_empty {
            break;
        }
        let next = path.parent();
        let _ = fs::remove_dir(path);
        current = next;
    }
}

fn gzip_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&serde_json::to_vec(value)?)?;
    Ok(encoder.finish()?)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn hmac_sign_base64(secret: &[u8], bytes: &[u8]) -> Result<String> {
    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|_| anyhow!("initialize HMAC signer"))?;
    mac.update(bytes);
    Ok(base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes()))
}

fn sqlite_table_exists(conn: &Connection, table: &str) -> Result<bool> {
    let exists = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            params![table],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    Ok(exists)
}

fn sqlite_table_columns(
    conn: &Connection,
    table: &str,
) -> Result<std::collections::HashSet<String>> {
    if !sqlite_table_exists(conn, table)? {
        return Ok(std::collections::HashSet::new());
    }
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    let mut columns = std::collections::HashSet::new();
    for row in rows {
        columns.insert(row?);
    }
    Ok(columns)
}

fn parse_rfc3339_epoch_ms(value: &str) -> Option<u128> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|instant| instant.timestamp_millis().max(0) as u128)
}

fn record_fetch_event(
    layout: &StateLayout,
    repo_root: Option<&str>,
    query_context: Option<&str>,
    provider: Option<&str>,
    query: Option<&str>,
    fetch: &WebFetchResult,
) -> Result<()> {
    write_event(
        layout,
        "web_fetch",
        &WebFetchPayload {
            query: query.map(str::to_string),
            repo_root: repo_root.map(str::to_string),
            context: query_context.map(str::to_string),
            provider: provider.map(str::to_string),
            url: fetch.url.clone(),
            status: fetch.status,
            fetched_at_epoch_ms: fetch.fetched_at_epoch_ms,
            cached: fetch.cached,
            content: fetch.content.clone(),
            ai_digested_content: fetch.ai_digested_content.clone(),
            ai_digested_kind: fetch.ai_digested_kind.clone(),
            relevance_score: fetch.relevance_score,
            error: fetch.error.clone(),
        },
    )?;

    if let Some(ai_digested_content) = fetch.ai_digested_content.as_ref() {
        if !ai_digested_content.trim().is_empty() {
            write_event(
                layout,
                "web_answer",
                &WebAnswerPayload {
                    query: query.map(str::to_string),
                    repo_root: repo_root.map(str::to_string),
                    context: query_context.map(str::to_string),
                    provider: provider.map(str::to_string),
                    url: fetch.url.clone(),
                    fetched_at_epoch_ms: fetch.fetched_at_epoch_ms,
                    cached: fetch.cached,
                    ai_digested_kind: fetch.ai_digested_kind.clone(),
                    ai_digested_content: ai_digested_content.clone(),
                    relevance_score: fetch.relevance_score,
                },
            )?;
        }
    }

    Ok(())
}

fn write_event<T: Serialize>(layout: &StateLayout, event_type: &str, payload: &T) -> Result<()> {
    let event_id = Uuid::new_v4().to_string();
    let created_at_ms = now_epoch_ms();
    let event_day_dir = event_day_dir(layout, event_type, created_at_ms);
    ensure_state_dir_secure(&event_day_dir)?;
    let path = event_day_dir.join(format!("{created_at_ms}-{event_id}.json"));
    let envelope = TelemetryEnvelope {
        schema_version: EVENT_SCHEMA_VERSION,
        event_id,
        event_type: event_type.to_string(),
        created_at_ms,
        payload,
    };
    let bytes = serde_json::to_vec_pretty(&envelope)?;
    fs::write(path, bytes)?;
    Ok(())
}

fn event_day_dir(layout: &StateLayout, event_type: &str, created_at_ms: u128) -> PathBuf {
    let day = event_day_bucket(created_at_ms);
    layout.mswarm_events_dir().join(event_type).join(day)
}

fn event_day_bucket(created_at_ms: u128) -> String {
    let timestamp_ms = i64::try_from(created_at_ms).unwrap_or(i64::MAX);
    if let Some(instant) = chrono::DateTime::<Utc>::from_timestamp_millis(timestamp_ms) {
        format!(
            "{:04}{:02}{:02}",
            instant.year(),
            instant.month(),
            instant.day()
        )
    } else {
        "unknown-date".to_string()
    }
}

fn normalize_repo_root(repo_root: Option<&Path>) -> Option<String> {
    repo_root.map(|path| path.display().to_string())
}

fn web_discovery_status_code(status: &WebDiscoveryStatus) -> String {
    match status.status {
        crate::orchestrator::web::WebDiscoveryStatusCode::Skipped => "skipped",
        crate::orchestrator::web::WebDiscoveryStatusCode::Disabled => "disabled",
        crate::orchestrator::web::WebDiscoveryStatusCode::Unavailable => "unavailable",
        crate::orchestrator::web::WebDiscoveryStatusCode::Served => "served",
    }
    .to_string()
}

fn now_epoch_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::web::{
        WebDiscoveryStatus, WebDiscoveryStatusCode, WebFetchResult, WebGateMeta,
    };
    use crate::web::ddg::{WebDiscoveryResponse, WebDiscoveryResult};
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::sync::{mpsc, Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};
    use tempfile::tempdir;

    struct MockUploadServer {
        addr: SocketAddr,
        shutdown: Option<mpsc::Sender<()>>,
        join: Option<thread::JoinHandle<()>>,
        body: Arc<Mutex<Option<String>>>,
    }

    impl MockUploadServer {
        fn spawn(response_body: &'static str) -> Result<Self> {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            listener.set_nonblocking(true)?;
            let addr = listener.local_addr()?;
            let (tx, rx) = mpsc::channel::<()>();
            let body = Arc::new(Mutex::new(None));
            let captured = Arc::clone(&body);
            let join = thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    if rx.try_recv().is_ok() {
                        break;
                    }
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                            let mut buffer = Vec::new();
                            let mut chunk = [0u8; 1024];
                            let mut header_end = None;
                            let mut content_length = 0usize;
                            loop {
                                match stream.read(&mut chunk) {
                                    Ok(0) => break,
                                    Ok(read) => {
                                        buffer.extend_from_slice(&chunk[..read]);
                                        if header_end.is_none() {
                                            if let Some(pos) = buffer
                                                .windows(4)
                                                .position(|window| window == b"\r\n\r\n")
                                            {
                                                header_end = Some(pos + 4);
                                                let headers =
                                                    String::from_utf8_lossy(&buffer[..pos + 4]);
                                                for line in headers.lines() {
                                                    if let Some((name, value)) =
                                                        line.split_once(':')
                                                    {
                                                        if name
                                                            .eq_ignore_ascii_case("content-length")
                                                        {
                                                            content_length = value
                                                                .trim()
                                                                .parse::<usize>()
                                                                .unwrap_or(0);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        if let Some(end) = header_end {
                                            let body_len = buffer.len().saturating_sub(end);
                                            if body_len >= content_length {
                                                break;
                                            }
                                        }
                                    }
                                    Err(err)
                                        if err.kind() == std::io::ErrorKind::WouldBlock
                                            || err.kind() == std::io::ErrorKind::TimedOut =>
                                    {
                                        break;
                                    }
                                    Err(_) => break,
                                }
                            }

                            if let Some(end) = header_end {
                                let body_bytes = buffer[end..].to_vec();
                                *captured.lock().expect("lock body") =
                                    Some(String::from_utf8_lossy(&body_bytes).into_owned());
                            }

                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                response_body.len(),
                                response_body
                            );
                            let _ = stream.write_all(response.as_bytes());
                            let _ = stream.flush();
                            break;
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            if Instant::now() > deadline {
                                break;
                            }
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
            });
            Ok(Self {
                addr,
                shutdown: Some(tx),
                join: Some(join),
                body,
            })
        }

        fn base_url(&self) -> String {
            format!("http://{}", self.addr)
        }

        fn body(&self) -> Option<String> {
            self.body.lock().expect("lock body").clone()
        }
    }

    impl Drop for MockUploadServer {
        fn drop(&mut self) {
            if let Some(tx) = self.shutdown.take() {
                let _ = tx.send(());
            }
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }

    #[test]
    fn resolve_state_layout_creates_mswarm_dirs() {
        let temp = tempdir().expect("tempdir");
        let layout = resolve_state_layout(Some(temp.path())).expect("resolve layout");
        assert!(layout.mswarm_dir().exists());
        assert!(layout.mswarm_events_dir().exists());
        assert!(layout.mswarm_packages_pending_dir().exists());
    }

    #[test]
    fn record_web_research_writes_search_fetch_and_answer_events() {
        let temp = tempdir().expect("tempdir");
        let status = WebDiscoveryStatus {
            status: WebDiscoveryStatusCode::Served,
            reason: Some("ok".to_string()),
            message: None,
            unavailable: None,
            discovery: Some(WebDiscoveryResponse {
                provider: "mswarm".to_string(),
                query: "rust reqwest docs".to_string(),
                results: vec![
                    WebDiscoveryResult {
                        url: "https://docs.rs/reqwest".to_string(),
                    },
                    WebDiscoveryResult {
                        url: "https://crates.io/crates/reqwest".to_string(),
                    },
                ],
            }),
            fetches: Some(vec![WebFetchResult {
                url: "https://docs.rs/reqwest".to_string(),
                status: Some(200),
                fetched_at_epoch_ms: Some(123),
                cached: false,
                content: Some("reqwest docs body".to_string()),
                ai_digested_content: Some("reqwest summary".to_string()),
                ai_digested_kind: Some("summary".to_string()),
                relevance_score: Some(0.92),
                debug_html: None,
                debug_dom_text: None,
                error: None,
                debug: None,
            }]),
            debug: None,
            gate: WebGateMeta {
                enabled: true,
                forced: true,
                threshold: 0.7,
                top_score: None,
                top_score_normalized: None,
                top_score_normalized_camel: None,
                local_match_ratio: None,
                local_match_ratio_camel: None,
            },
        };

        record_web_research(
            Some(temp.path()),
            Some(Path::new("/tmp/repo")),
            "rust reqwest docs",
            Some("api_reference"),
            &status,
        )
        .expect("record web research");

        let events_root = StateLayout::new(temp.path().to_path_buf()).mswarm_events_dir();
        assert_eq!(json_file_count(&events_root.join("web_search")), 1);
        assert_eq!(json_file_count(&events_root.join("web_fetch")), 1);
        assert_eq!(json_file_count(&events_root.join("web_answer")), 1);
        let search_event = first_json_event(&events_root.join("web_search"));
        assert_eq!(
            search_event["payload"]["context"].as_str(),
            Some("api_reference")
        );
        let answer_event = first_json_event(&events_root.join("web_answer"));
        assert_eq!(
            answer_event["payload"]["context"].as_str(),
            Some("api_reference")
        );
    }

    #[test]
    fn record_delegation_failure_writes_event() {
        let temp = tempdir().expect("tempdir");
        record_delegation_failure(
            Some(temp.path()),
            "2026-03-18T12:00:00Z",
            Some("mcp"),
            "local_completion_failed",
            "refactor_simple",
            "draft_only",
            Some("repo-id"),
            Some("/tmp/repo"),
            "agent:qwen3-coder",
            2,
            "fallback_to_primary",
            "request timed out",
        )
        .expect("record failure");

        let events_root = StateLayout::new(temp.path().to_path_buf()).mswarm_events_dir();
        assert_eq!(json_file_count(&events_root.join("delegation_failure")), 1);
    }

    #[test]
    fn export_delegation_savings_writes_snapshot_event() {
        let temp = tempdir().expect("tempdir");
        let layout = StateLayout::new(temp.path().to_path_buf());
        layout.ensure_global_dirs().expect("ensure state dirs");

        let metrics = crate::metrics::Metrics::default();
        metrics.inc_delegate_request();
        metrics.inc_delegate_offloaded();
        metrics.record_delegate_token_estimate(42);
        metrics.record_delegate_local_tokens(30);
        metrics.record_delegate_primary_tokens(12);
        metrics.record_delegate_token_savings(30);
        metrics.record_delegate_local_cost_micros(500);
        metrics.record_delegate_primary_cost_micros(200);
        metrics.record_delegate_cost_savings_micros(700);
        crate::delegation_telemetry::persist_metrics(Some(temp.path()), &metrics, None, None);

        let app_config = AppConfig::default();
        let exported = export_delegation_savings_to_spool(&layout, &app_config)
            .expect("export delegation savings");
        assert_eq!(exported, 1);

        let event = first_json_event(
            &layout
                .mswarm_events_dir()
                .join("delegation_savings_snapshot"),
        );
        assert_eq!(
            event["payload"]["delegate_cost_savings_micros_total"].as_u64(),
            Some(700)
        );
        assert_eq!(
            event["payload"]["delegate_avoided_primary_cost_micros_total"].as_u64(),
            Some(1_200)
        );
        assert_eq!(event["payload"]["project_count"].as_u64(), Some(0));
    }

    #[test]
    fn create_and_upload_pending_package_clears_spool_files() {
        let temp = tempdir().expect("tempdir");
        let server = MockUploadServer::spawn(r#"{"accepted":true}"#).expect("spawn server");
        let layout = StateLayout::new(temp.path().to_path_buf());
        layout.ensure_global_dirs().expect("ensure state dirs");
        write_event(
            &layout,
            "web_answer",
            &json!({
                "query": "reqwest rust docs",
                "provider": "brave_search",
                "url": "https://docs.rs/reqwest/latest/reqwest/",
                "ai_digested_content": "Use reqwest::Client."
            }),
        )
        .expect("write event");
        let rating_day = event_day_bucket(now_epoch_ms());
        let rating_dir = layout.mswarm_ratings_dir().join(&rating_day);
        ensure_state_dir_secure(&rating_dir).expect("rating dir");
        fs::write(
            rating_dir.join("rating-1.json"),
            serde_json::to_vec_pretty(&json!({
                "schema_version": 1,
                "event_id": "rating-1",
                "event_type": "mcoda_agent_rating",
                "created_at_ms": now_epoch_ms(),
                "payload": { "agent_id": "agent-1", "quality_score": 9.1 }
            }))
            .expect("serialize rating"),
        )
        .expect("write rating");

        let auth = UploadAuth {
            base_url: format!("{}/", server.base_url()),
            api_key: None,
            consent_token: "token-123".to_string(),
            client_id: "free-client-123".to_string(),
            client_type: "free_docdex_client".to_string(),
            consent_policy_version: "2026-03-18".to_string(),
            signing_secret: "upload-secret-123".to_string(),
        };
        let pending = create_pending_package(&layout, &auth)
            .expect("create package")
            .expect("pending metadata");
        assert_eq!(pending.event_count, 1);
        assert_eq!(pending.rating_count, 1);
        let upload_result = upload_queued_packages(&layout, &auth).expect("upload queued");
        assert_eq!(upload_result.uploaded, 1);
        assert_eq!(upload_result.failed, 0);
        assert_eq!(json_file_count(&layout.mswarm_events_dir()), 0);
        assert_eq!(json_file_count(&layout.mswarm_ratings_dir()), 0);
        assert!(
            collect_package_metadata_paths(&layout.mswarm_packages_pending_dir())
                .expect("pending metadata")
                .is_empty()
        );
        let captured = server.body().expect("captured upload body");
        assert!(captured.contains("\"payload_encoding\":\"gzip+json\""));
    }

    fn json_file_count(root: &Path) -> usize {
        if !root.exists() {
            return 0;
        }
        let mut count = 0usize;
        let mut stack = vec![root.to_path_buf()];
        while let Some(path) = stack.pop() {
            let Ok(entries) = fs::read_dir(path) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().and_then(|value| value.to_str()) == Some("json") {
                    count += 1;
                }
            }
        }
        count
    }

    fn first_json_event(root: &Path) -> serde_json::Value {
        let mut stack = vec![root.to_path_buf()];
        while let Some(path) = stack.pop() {
            let Ok(entries) = fs::read_dir(path) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|value| value.to_str()) == Some("json") {
                    let bytes = fs::read(path).expect("read event");
                    return serde_json::from_slice(&bytes).expect("parse event");
                }
            }
        }
        panic!("expected at least one json event under {}", root.display());
    }
}
