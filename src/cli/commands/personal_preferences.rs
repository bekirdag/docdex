use anyhow::{anyhow, Result};
use reqwest::Method;
use serde_json::json;

use crate::cli::http_client::CliHttpClient;

use super::emit_json_or_error;

pub(crate) async fn run(command: crate::cli::PersonalPreferencesCommand) -> Result<()> {
    match command {
        crate::cli::PersonalPreferencesCommand::Status => run_status().await,
        crate::cli::PersonalPreferencesCommand::Categories => run_categories().await,
        crate::cli::PersonalPreferencesCommand::RetentionPolicies => run_retention_policies().await,
        crate::cli::PersonalPreferencesCommand::List {
            status,
            limit,
            offset,
        } => run_list(status, limit, offset).await,
        crate::cli::PersonalPreferencesCommand::Read { capture_id } => run_read(capture_id).await,
        crate::cli::PersonalPreferencesCommand::Search {
            query,
            limit,
            include_sensitive,
        } => run_search(query, limit, include_sensitive).await,
        crate::cli::PersonalPreferencesCommand::Reviews {
            status,
            limit,
            offset,
        } => run_reviews(status, limit, offset).await,
        crate::cli::PersonalPreferencesCommand::Review {
            record_id,
            verdict,
            notes,
        } => run_review(record_id, verdict, notes).await,
        crate::cli::PersonalPreferencesCommand::Process {
            limit,
            retry_failed,
            retry_stale_processing_ms,
        } => run_process(limit, retry_failed, retry_stale_processing_ms).await,
        crate::cli::PersonalPreferencesCommand::Scan { limit } => run_scan(limit).await,
        crate::cli::PersonalPreferencesCommand::Prune {
            raw_retention_days,
            derived_retention_days,
            apply,
        } => run_prune(raw_retention_days, derived_retention_days, apply).await,
        crate::cli::PersonalPreferencesCommand::Export { capture_id } => {
            run_export(capture_id).await
        }
        crate::cli::PersonalPreferencesCommand::Redact { capture_id } => {
            run_redact(capture_id).await
        }
        crate::cli::PersonalPreferencesCommand::Delete { capture_id } => {
            run_delete(capture_id).await
        }
        crate::cli::PersonalPreferencesCommand::Purge { include_exports } => {
            run_purge(include_exports).await
        }
        crate::cli::PersonalPreferencesCommand::Claims { command } => run_claims(command).await,
        crate::cli::PersonalPreferencesCommand::Feedback { command } => run_feedback(command).await,
        crate::cli::PersonalPreferencesCommand::OperatorEvents { command } => {
            run_operator_events(command).await
        }
        crate::cli::PersonalPreferencesCommand::Snapshots { command } => {
            run_snapshots(command).await
        }
        crate::cli::PersonalPreferencesCommand::Routines { command } => run_routines(command).await,
        crate::cli::PersonalPreferencesCommand::MindMap {
            query,
            limit,
            include_sensitive,
        } => run_mind_map(query, limit, include_sensitive).await,
        crate::cli::PersonalPreferencesCommand::Playbooks {
            min_confidence,
            min_support_count,
            include_sensitive,
        } => run_playbooks(min_confidence, min_support_count, include_sensitive).await,
        crate::cli::PersonalPreferencesCommand::Skills { command } => run_skills(command).await,
        crate::cli::PersonalPreferencesCommand::Clone { command } => run_clone(command).await,
    }
}

async fn run_status() -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(Method::GET, "/v1/personal-preferences/status")
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences status").await
}

async fn run_categories() -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(Method::GET, "/v1/personal-preferences/categories")
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences categories").await
}

async fn run_retention_policies() -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(Method::GET, "/v1/personal-preferences/retention-policies")
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences retention policies").await
}

async fn run_list(status: Option<String>, limit: usize, offset: usize) -> Result<()> {
    let client = CliHttpClient::new()?;
    let mut req = client.request(Method::GET, "/v1/personal-preferences/captures");
    req = req.query(&[("limit", limit.max(1)), ("offset", offset)]);
    if let Some(status) = status
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        req = req.query(&[("status", status)]);
    }
    let resp = req.send().await?;
    emit_json_or_error(resp, "personal preferences list").await
}

async fn run_read(capture_id: String) -> Result<()> {
    let client = CliHttpClient::new()?;
    let path = format!("/v1/personal-preferences/captures/{capture_id}");
    let resp = client.request(Method::GET, &path).send().await?;
    emit_json_or_error(resp, "personal preferences read").await
}

async fn run_search(query: String, limit: usize, include_sensitive: bool) -> Result<()> {
    let client = CliHttpClient::new()?;
    let req = client
        .request(Method::GET, "/v1/personal-preferences/search")
        .query(&[
            ("q", query.as_str()),
            ("limit", &limit.max(1).to_string()),
            (
                "include_sensitive",
                if include_sensitive { "true" } else { "false" },
            ),
        ]);
    let resp = req.send().await?;
    emit_json_or_error(resp, "personal preferences search").await
}

async fn run_reviews(status: Option<String>, limit: usize, offset: usize) -> Result<()> {
    let client = CliHttpClient::new()?;
    let mut req = client.request(Method::GET, "/v1/personal-preferences/reviews");
    req = req.query(&[("limit", limit.max(1)), ("offset", offset)]);
    if let Some(status) = status
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        req = req.query(&[("status", status)]);
    }
    let resp = req.send().await?;
    emit_json_or_error(resp, "personal preferences reviews").await
}

async fn run_review(record_id: String, verdict: String, notes: Option<String>) -> Result<()> {
    let client = CliHttpClient::new()?;
    let path = format!("/v1/personal-preferences/reviews/{record_id}");
    let resp = client
        .request(Method::POST, &path)
        .json(&json!({
            "verdict": verdict,
            "notes": notes,
        }))
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences review").await
}

async fn run_process(
    limit: Option<usize>,
    retry_failed: bool,
    retry_stale_processing_ms: Option<i64>,
) -> Result<()> {
    if let Some(stale_ms) = retry_stale_processing_ms {
        if stale_ms < 0 {
            return Err(anyhow!("retry_stale_processing_ms must be >= 0"));
        }
    }
    let client = CliHttpClient::new()?;
    let resp = client
        .request(Method::POST, "/v1/personal-preferences/process")
        .json(&json!({
            "limit": limit,
            "retry_failed": retry_failed,
            "retry_stale_processing_ms": retry_stale_processing_ms,
        }))
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences process").await
}

async fn run_scan(limit: Option<usize>) -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(Method::POST, "/v1/personal-preferences/scan")
        .json(&json!({ "limit": limit }))
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences scan").await
}

async fn run_prune(
    raw_retention_days: Option<u32>,
    derived_retention_days: Option<u32>,
    apply: bool,
) -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(Method::POST, "/v1/personal-preferences/prune")
        .json(&json!({
            "raw_retention_days": raw_retention_days,
            "derived_retention_days": derived_retention_days,
            "apply": apply,
        }))
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences prune").await
}

async fn run_export(capture_id: Option<String>) -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(Method::POST, "/v1/personal-preferences/export")
        .json(&json!({ "capture_id": capture_id }))
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences export").await
}

async fn run_redact(capture_id: String) -> Result<()> {
    let client = CliHttpClient::new()?;
    let path = format!("/v1/personal-preferences/captures/{capture_id}/redact");
    let resp = client.request(Method::POST, &path).send().await?;
    emit_json_or_error(resp, "personal preferences redact").await
}

async fn run_delete(capture_id: String) -> Result<()> {
    let client = CliHttpClient::new()?;
    let path = format!("/v1/personal-preferences/captures/{capture_id}");
    let resp = client.request(Method::DELETE, &path).send().await?;
    emit_json_or_error(resp, "personal preferences delete").await
}

async fn run_purge(include_exports: bool) -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(Method::POST, "/v1/personal-preferences/purge")
        .json(&json!({ "include_exports": include_exports }))
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences purge").await
}

async fn run_claims(command: crate::cli::PersonalPreferencesClaimsCommand) -> Result<()> {
    match command {
        crate::cli::PersonalPreferencesClaimsCommand::List {
            query,
            truth_status,
            claim_origin,
            include_sensitive,
            limit,
            offset,
        } => {
            run_claims_list(
                query,
                truth_status,
                claim_origin,
                include_sensitive,
                limit,
                offset,
            )
            .await
        }
        crate::cli::PersonalPreferencesClaimsCommand::Read { claim_id } => {
            run_claim_read(claim_id).await
        }
        crate::cli::PersonalPreferencesClaimsCommand::Review {
            claim_id,
            verdict,
            notes,
        } => run_claim_review(claim_id, verdict, notes).await,
        crate::cli::PersonalPreferencesClaimsCommand::Override {
            claim_id,
            value,
            notes,
        } => run_claim_override(claim_id, value, notes).await,
        crate::cli::PersonalPreferencesClaimsCommand::Forget { claim_id, notes } => {
            run_claim_forget(claim_id, notes).await
        }
    }
}

async fn run_feedback(command: crate::cli::PersonalPreferencesFeedbackCommand) -> Result<()> {
    match command {
        crate::cli::PersonalPreferencesFeedbackCommand::Add {
            event_type,
            claim_id,
            capture_id,
            category,
            attribute,
            value,
            notes,
            metadata_json,
        } => {
            let metadata = match metadata_json {
                Some(raw) => serde_json::from_str(&raw)
                    .map_err(|err| anyhow!("invalid --metadata-json payload: {err}"))?,
                None => serde_json::Value::Null,
            };
            run_feedback_add(
                event_type, claim_id, capture_id, category, attribute, value, notes, metadata,
            )
            .await
        }
    }
}

async fn run_operator_events(
    command: crate::cli::PersonalPreferencesOperatorEventsCommand,
) -> Result<()> {
    match command {
        crate::cli::PersonalPreferencesOperatorEventsCommand::List {
            event_kind,
            action,
            repo_root,
            limit,
            offset,
        } => run_operator_events_list(event_kind, action, repo_root, limit, offset).await,
        crate::cli::PersonalPreferencesOperatorEventsCommand::Record {
            event_kind,
            action,
            summary,
            command_text,
            source_session_id,
            repo_id,
            repo_root,
            capture_id,
            artifact_path,
            occurred_at_ms,
            metadata_json,
        } => {
            let metadata = match metadata_json {
                Some(raw) => serde_json::from_str(&raw)
                    .map_err(|err| anyhow!("invalid --metadata-json payload: {err}"))?,
                None => serde_json::Value::Null,
            };
            run_operator_event_record(
                event_kind,
                action,
                summary,
                command_text,
                source_session_id,
                repo_id,
                repo_root,
                capture_id,
                artifact_path,
                occurred_at_ms,
                metadata,
            )
            .await
        }
        crate::cli::PersonalPreferencesOperatorEventsCommand::ScanArtifacts {
            repo_root,
            limit,
        } => run_operator_events_scan_artifacts(repo_root, limit).await,
    }
}

async fn run_snapshots(command: crate::cli::PersonalPreferencesSnapshotsCommand) -> Result<()> {
    match command {
        crate::cli::PersonalPreferencesSnapshotsCommand::List { limit, offset } => {
            run_snapshots_list(limit, offset).await
        }
        crate::cli::PersonalPreferencesSnapshotsCommand::Read { snapshot_id } => {
            run_snapshot_read(snapshot_id).await
        }
        crate::cli::PersonalPreferencesSnapshotsCommand::Rebuild => run_snapshots_rebuild().await,
    }
}

async fn run_routines(command: crate::cli::PersonalPreferencesRoutinesCommand) -> Result<()> {
    match command {
        crate::cli::PersonalPreferencesRoutinesCommand::List { limit, offset } => {
            run_routines_list(limit, offset).await
        }
        crate::cli::PersonalPreferencesRoutinesCommand::Read { routine_id } => {
            run_routine_read(routine_id).await
        }
        crate::cli::PersonalPreferencesRoutinesCommand::Explain { routine_id } => {
            run_routine_explain(routine_id).await
        }
        crate::cli::PersonalPreferencesRoutinesCommand::Rebuild => run_routines_rebuild().await,
    }
}

async fn run_clone(command: crate::cli::PersonalPreferencesCloneCommand) -> Result<()> {
    match command {
        crate::cli::PersonalPreferencesCloneCommand::Context {
            query,
            mode,
            allow_sensitive,
            current_repo_root,
            max_records,
            budget_tokens,
        } => {
            run_clone_request(
                "/v1/personal-preferences/clone/context",
                query,
                mode,
                allow_sensitive,
                current_repo_root,
                max_records,
                budget_tokens,
            )
            .await
        }
        crate::cli::PersonalPreferencesCloneCommand::Directive {
            query,
            agent_id,
            mode,
            allow_sensitive,
            current_repo_root,
            max_records,
            budget_tokens,
            task_type,
            risk_level,
            current_files,
            current_plan_path,
            enforcement_level,
        } => {
            run_clone_directive_request(
                query,
                agent_id,
                mode,
                allow_sensitive,
                current_repo_root,
                max_records,
                budget_tokens,
                task_type,
                risk_level,
                current_files,
                current_plan_path,
                enforcement_level,
            )
            .await
        }
        crate::cli::PersonalPreferencesCloneCommand::Explain {
            query,
            mode,
            allow_sensitive,
            current_repo_root,
            max_records,
            budget_tokens,
        } => {
            run_clone_request(
                "/v1/personal-preferences/clone/explain",
                query,
                mode,
                allow_sensitive,
                current_repo_root,
                max_records,
                budget_tokens,
            )
            .await
        }
        crate::cli::PersonalPreferencesCloneCommand::Evaluate {
            query,
            mode,
            allow_sensitive,
            current_repo_root,
            max_records,
            budget_tokens,
        } => {
            run_clone_request(
                "/v1/personal-preferences/clone/evaluate",
                query,
                mode,
                allow_sensitive,
                current_repo_root,
                max_records,
                budget_tokens,
            )
            .await
        }
        crate::cli::PersonalPreferencesCloneCommand::ReplayEvaluate {
            query,
            mode,
            allow_sensitive,
            current_repo_root,
            max_records,
            budget_tokens,
            expected_categories,
        } => {
            run_clone_replay_request(
                query,
                mode,
                allow_sensitive,
                current_repo_root,
                max_records,
                budget_tokens,
                expected_categories,
            )
            .await
        }
        crate::cli::PersonalPreferencesCloneCommand::ReplayDataset {
            ci_subset,
            limit,
            current_repo_root,
        } => run_clone_replay_dataset_request(ci_subset, limit, current_repo_root).await,
        crate::cli::PersonalPreferencesCloneCommand::ReplaySuite {
            ci_subset,
            limit,
            threshold,
            allow_sensitive,
            current_repo_root,
            max_records,
            budget_tokens,
        } => {
            run_clone_replay_suite_request(
                ci_subset,
                limit,
                threshold,
                allow_sensitive,
                current_repo_root,
                max_records,
                budget_tokens,
            )
            .await
        }
    }
}

async fn run_claims_list(
    query: Option<String>,
    truth_status: Option<String>,
    claim_origin: Option<String>,
    include_sensitive: bool,
    limit: usize,
    offset: usize,
) -> Result<()> {
    let client = CliHttpClient::new()?;
    let mut req = client.request(Method::GET, "/v1/personal-preferences/claims");
    req = req.query(&[
        ("limit", limit.max(1).to_string()),
        ("offset", offset.to_string()),
        ("include_sensitive", include_sensitive.to_string()),
    ]);
    if let Some(query) = query
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        req = req.query(&[("query", query)]);
    }
    if let Some(truth_status) = truth_status
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        req = req.query(&[("truth_status", truth_status)]);
    }
    if let Some(claim_origin) = claim_origin
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        req = req.query(&[("claim_origin", claim_origin)]);
    }
    let resp = req.send().await?;
    emit_json_or_error(resp, "personal preferences claims").await
}

async fn run_claim_read(claim_id: String) -> Result<()> {
    let client = CliHttpClient::new()?;
    let path = format!("/v1/personal-preferences/claims/{claim_id}");
    let resp = client.request(Method::GET, &path).send().await?;
    emit_json_or_error(resp, "personal preferences claim").await
}

async fn run_claim_review(claim_id: String, verdict: String, notes: Option<String>) -> Result<()> {
    let client = CliHttpClient::new()?;
    let path = format!("/v1/personal-preferences/claims/{claim_id}/review");
    let resp = client
        .request(Method::POST, &path)
        .json(&json!({
            "verdict": verdict,
            "notes": notes,
        }))
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences claim review").await
}

async fn run_claim_override(claim_id: String, value: String, notes: Option<String>) -> Result<()> {
    let client = CliHttpClient::new()?;
    let path = format!("/v1/personal-preferences/claims/{claim_id}/override");
    let resp = client
        .request(Method::POST, &path)
        .json(&json!({
            "value": value,
            "notes": notes,
        }))
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences claim override").await
}

async fn run_claim_forget(claim_id: String, notes: Option<String>) -> Result<()> {
    let client = CliHttpClient::new()?;
    let path = format!("/v1/personal-preferences/claims/{claim_id}/forget");
    let resp = client
        .request(Method::POST, &path)
        .json(&json!({
            "notes": notes,
        }))
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences claim forget").await
}

async fn run_feedback_add(
    event_type: String,
    claim_id: Option<String>,
    capture_id: Option<String>,
    category: Option<String>,
    attribute: Option<String>,
    value: Option<String>,
    notes: Option<String>,
    metadata: serde_json::Value,
) -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(Method::POST, "/v1/personal-preferences/feedback")
        .json(&json!({
            "event_type": event_type,
            "claim_id": claim_id,
            "capture_id": capture_id,
            "category": category,
            "attribute": attribute,
            "value": value,
            "notes": notes,
            "metadata": metadata,
        }))
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences feedback").await
}

async fn run_operator_events_list(
    event_kind: Option<String>,
    action: Option<String>,
    repo_root: Option<String>,
    limit: usize,
    offset: usize,
) -> Result<()> {
    let client = CliHttpClient::new()?;
    let mut req = client.request(Method::GET, "/v1/personal-preferences/operator-events");
    req = req.query(&[
        ("limit", limit.max(1).to_string()),
        ("offset", offset.to_string()),
    ]);
    if let Some(event_kind) = event_kind
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        req = req.query(&[("event_kind", event_kind)]);
    }
    if let Some(action) = action
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        req = req.query(&[("action", action)]);
    }
    if let Some(repo_root) = repo_root
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        req = req.query(&[("repo_root", repo_root)]);
    }
    let resp = req.send().await?;
    emit_json_or_error(resp, "personal preferences operator events").await
}

#[allow(clippy::too_many_arguments)]
async fn run_operator_event_record(
    event_kind: Option<String>,
    action: String,
    summary: Option<String>,
    command_text: Option<String>,
    source_session_id: Option<String>,
    repo_id: Option<String>,
    repo_root: Option<String>,
    capture_id: Option<String>,
    artifact_path: Option<String>,
    occurred_at_ms: Option<i64>,
    metadata: serde_json::Value,
) -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(Method::POST, "/v1/personal-preferences/operator-events")
        .json(&json!({
            "event_kind": event_kind,
            "action": action,
            "summary": summary,
            "command_text": command_text,
            "source_session_id": source_session_id,
            "repo_id": repo_id,
            "repo_root": repo_root,
            "capture_id": capture_id,
            "artifact_path": artifact_path,
            "occurred_at_ms": occurred_at_ms,
            "metadata": metadata,
        }))
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences operator event record").await
}

async fn run_operator_events_scan_artifacts(
    repo_root: Option<std::path::PathBuf>,
    limit: Option<usize>,
) -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(
            Method::POST,
            "/v1/personal-preferences/operator-events/scan-artifacts",
        )
        .json(&json!({
            "repo_root": repo_root.map(|path| path.display().to_string()),
            "limit": limit,
        }))
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences operator artifact scan").await
}

async fn run_snapshots_list(limit: usize, offset: usize) -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(Method::GET, "/v1/personal-preferences/snapshots")
        .query(&[
            ("limit", limit.max(1).to_string()),
            ("offset", offset.to_string()),
        ])
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences snapshots").await
}

async fn run_snapshot_read(snapshot_id: String) -> Result<()> {
    let client = CliHttpClient::new()?;
    let path = format!("/v1/personal-preferences/snapshots/{snapshot_id}");
    let resp = client.request(Method::GET, &path).send().await?;
    emit_json_or_error(resp, "personal preferences snapshot").await
}

async fn run_snapshots_rebuild() -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(Method::POST, "/v1/personal-preferences/snapshots/rebuild")
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences snapshot rebuild").await
}

async fn run_routines_list(limit: usize, offset: usize) -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(Method::GET, "/v1/personal-preferences/routines")
        .query(&[
            ("limit", limit.max(1).to_string()),
            ("offset", offset.to_string()),
        ])
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences routines").await
}

async fn run_routine_read(routine_id: String) -> Result<()> {
    let client = CliHttpClient::new()?;
    let path = format!("/v1/personal-preferences/routines/{routine_id}");
    let resp = client.request(Method::GET, &path).send().await?;
    emit_json_or_error(resp, "personal preferences routine").await
}

async fn run_routine_explain(routine_id: String) -> Result<()> {
    let client = CliHttpClient::new()?;
    let path = format!("/v1/personal-preferences/routines/{routine_id}/explain");
    let resp = client.request(Method::GET, &path).send().await?;
    emit_json_or_error(resp, "personal preferences routine explain").await
}

async fn run_routines_rebuild() -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(Method::POST, "/v1/personal-preferences/routines/rebuild")
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences routines rebuild").await
}

async fn run_mind_map(query: Option<String>, limit: usize, include_sensitive: bool) -> Result<()> {
    let client = CliHttpClient::new()?;
    let mut req = client.request(Method::GET, "/v1/personal-preferences/mind-map");
    req = req.query(&[
        ("limit", limit.max(4).to_string()),
        ("include_sensitive", include_sensitive.to_string()),
    ]);
    if let Some(query) = query
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        req = req.query(&[("query", query)]);
    }
    let resp = req.send().await?;
    emit_json_or_error(resp, "personal preferences mind map").await
}

async fn run_playbooks(
    min_confidence: f32,
    min_support_count: usize,
    include_sensitive: bool,
) -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(Method::GET, "/v1/personal-preferences/playbooks")
        .query(&[
            (
                "min_confidence",
                min_confidence.clamp(0.0, 0.99).to_string(),
            ),
            ("min_support_count", min_support_count.max(1).to_string()),
            ("include_sensitive", include_sensitive.to_string()),
        ])
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences playbooks").await
}

async fn run_skills(command: crate::cli::PersonalPreferencesSkillsCommand) -> Result<()> {
    match command {
        crate::cli::PersonalPreferencesSkillsCommand::List => run_skills_list().await,
        crate::cli::PersonalPreferencesSkillsCommand::Events { limit, offset } => {
            run_skills_events(limit, offset).await
        }
        crate::cli::PersonalPreferencesSkillsCommand::Read { skill_id } => {
            run_skills_read(skill_id).await
        }
        crate::cli::PersonalPreferencesSkillsCommand::Preview {
            min_confidence,
            min_support_count,
            include_sensitive,
            terminals,
        } => {
            run_skills_preview(
                min_confidence,
                min_support_count,
                include_sensitive,
                terminals,
            )
            .await
        }
        crate::cli::PersonalPreferencesSkillsCommand::Render {
            min_confidence,
            min_support_count,
            include_sensitive,
            terminals,
        } => {
            run_skills_render(
                min_confidence,
                min_support_count,
                include_sensitive,
                terminals,
            )
            .await
        }
        crate::cli::PersonalPreferencesSkillsCommand::Validate { skill_id } => {
            run_skills_action(skill_id, "validate", Vec::new(), None).await
        }
        crate::cli::PersonalPreferencesSkillsCommand::Install {
            skill_id,
            terminals,
        } => run_skills_action(skill_id, "install", terminals, None).await,
        crate::cli::PersonalPreferencesSkillsCommand::Disable { skill_id, reason } => {
            run_skills_action(skill_id, "disable", Vec::new(), reason).await
        }
        crate::cli::PersonalPreferencesSkillsCommand::Rollback {
            skill_id,
            terminals,
        } => run_skills_action(skill_id, "rollback", terminals, None).await,
        crate::cli::PersonalPreferencesSkillsCommand::Sync {
            min_confidence,
            min_support_count,
            include_sensitive,
            no_install,
            terminals,
        } => {
            run_skills_sync(
                min_confidence,
                min_support_count,
                include_sensitive,
                no_install,
                terminals,
            )
            .await
        }
        crate::cli::PersonalPreferencesSkillsCommand::Autopilot {
            once: _,
            min_confidence,
            min_support_count,
            include_sensitive,
            no_install,
            terminals,
        } => {
            run_skills_autopilot(
                min_confidence,
                min_support_count,
                include_sensitive,
                no_install,
                terminals,
            )
            .await
        }
    }
}

async fn run_skills_list() -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(Method::GET, "/v1/personal-preferences/generated-skills")
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences generated skills").await
}

async fn run_skills_read(skill_id: String) -> Result<()> {
    let client = CliHttpClient::new()?;
    let path = format!("/v1/personal-preferences/generated-skills/{skill_id}");
    let resp = client.request(Method::GET, &path).send().await?;
    emit_json_or_error(resp, "personal preferences generated skill").await
}

async fn run_skills_events(limit: usize, offset: usize) -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(
            Method::GET,
            "/v1/personal-preferences/generated-skills/events",
        )
        .query(&[
            ("limit", limit.max(1).to_string()),
            ("offset", offset.to_string()),
        ])
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences generated skill events").await
}

async fn run_skills_preview(
    min_confidence: f32,
    min_support_count: usize,
    include_sensitive: bool,
    terminals: Vec<String>,
) -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(
            Method::POST,
            "/v1/personal-preferences/generated-skills/preview",
        )
        .json(&json!({
            "min_confidence": min_confidence.clamp(0.0, 0.99),
            "min_support_count": min_support_count.max(1),
            "include_sensitive": include_sensitive,
            "install": false,
            "terminals": terminals,
        }))
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences generated skills preview").await
}

async fn run_skills_render(
    min_confidence: f32,
    min_support_count: usize,
    include_sensitive: bool,
    terminals: Vec<String>,
) -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(
            Method::POST,
            "/v1/personal-preferences/generated-skills/render",
        )
        .json(&json!({
            "min_confidence": min_confidence.clamp(0.0, 0.99),
            "min_support_count": min_support_count.max(1),
            "include_sensitive": include_sensitive,
            "install": false,
            "terminals": terminals,
        }))
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences generated skills render").await
}

async fn run_skills_action(
    skill_id: String,
    action: &str,
    terminals: Vec<String>,
    reason: Option<String>,
) -> Result<()> {
    let client = CliHttpClient::new()?;
    let path = format!("/v1/personal-preferences/generated-skills/{skill_id}/{action}");
    let resp = client
        .request(Method::POST, &path)
        .json(&json!({
            "skill_id": skill_id,
            "terminals": terminals,
            "reason": reason,
        }))
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences generated skill action").await
}

async fn run_skills_sync(
    min_confidence: f32,
    min_support_count: usize,
    include_sensitive: bool,
    no_install: bool,
    terminals: Vec<String>,
) -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(
            Method::POST,
            "/v1/personal-preferences/generated-skills/sync",
        )
        .json(&json!({
            "min_confidence": min_confidence.clamp(0.0, 0.99),
            "min_support_count": min_support_count.max(1),
            "include_sensitive": include_sensitive,
            "install": !no_install,
            "terminals": terminals,
        }))
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences generated skills sync").await
}

async fn run_skills_autopilot(
    min_confidence: f32,
    min_support_count: usize,
    include_sensitive: bool,
    no_install: bool,
    terminals: Vec<String>,
) -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(
            Method::POST,
            "/v1/personal-preferences/generated-skills/autopilot",
        )
        .json(&json!({
            "min_confidence": min_confidence.clamp(0.0, 0.99),
            "min_support_count": min_support_count.max(1),
            "include_sensitive": include_sensitive,
            "install": !no_install,
            "terminals": terminals,
        }))
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences generated skills autopilot").await
}

async fn run_clone_request(
    path: &str,
    query: String,
    mode: Option<String>,
    allow_sensitive: bool,
    current_repo_root: Option<String>,
    max_records: Option<usize>,
    budget_tokens: Option<usize>,
) -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(Method::POST, path)
        .json(&json!({
            "query": query,
            "mode": mode,
            "allow_sensitive": allow_sensitive,
            "current_repo_root": current_repo_root,
            "max_records": max_records,
            "budget_tokens": budget_tokens,
        }))
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences clone").await
}

#[allow(clippy::too_many_arguments)]
async fn run_clone_directive_request(
    query: String,
    agent_id: Option<String>,
    mode: Option<String>,
    allow_sensitive: bool,
    current_repo_root: Option<String>,
    max_records: Option<usize>,
    budget_tokens: Option<usize>,
    task_type: Option<String>,
    risk_level: Option<String>,
    current_files: Vec<String>,
    current_plan_path: Option<String>,
    enforcement_level: Option<String>,
) -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(Method::POST, "/v1/personal-preferences/clone/directive")
        .json(&json!({
            "query": query,
            "agent_id": agent_id,
            "mode": mode,
            "allow_sensitive": allow_sensitive,
            "current_repo_root": current_repo_root,
            "max_records": max_records,
            "budget_tokens": budget_tokens,
            "task_type": task_type,
            "risk_level": risk_level,
            "current_files": current_files,
            "current_plan_path": current_plan_path,
            "enforcement_level": enforcement_level,
        }))
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences clone directive").await
}

async fn run_clone_replay_request(
    query: String,
    mode: Option<String>,
    allow_sensitive: bool,
    current_repo_root: Option<String>,
    max_records: Option<usize>,
    budget_tokens: Option<usize>,
    expected_categories: Vec<String>,
) -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(
            Method::POST,
            "/v1/personal-preferences/clone/replay-evaluate",
        )
        .json(&json!({
            "query": query,
            "mode": mode,
            "allow_sensitive": allow_sensitive,
            "current_repo_root": current_repo_root,
            "max_records": max_records,
            "budget_tokens": budget_tokens,
            "expected_categories": expected_categories,
        }))
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences clone replay").await
}

async fn run_clone_replay_dataset_request(
    ci_subset: bool,
    limit: Option<usize>,
    current_repo_root: Option<String>,
) -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(
            Method::POST,
            "/v1/personal-preferences/clone/replay-dataset",
        )
        .json(&json!({
            "ci_subset": ci_subset,
            "limit": limit,
            "current_repo_root": current_repo_root,
        }))
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences clone replay dataset").await
}

async fn run_clone_replay_suite_request(
    ci_subset: bool,
    limit: Option<usize>,
    threshold: Option<f32>,
    allow_sensitive: bool,
    current_repo_root: Option<String>,
    max_records: Option<usize>,
    budget_tokens: Option<usize>,
) -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(Method::POST, "/v1/personal-preferences/clone/replay-suite")
        .json(&json!({
            "ci_subset": ci_subset,
            "limit": limit,
            "threshold": threshold,
            "allow_sensitive": allow_sensitive,
            "current_repo_root": current_repo_root,
            "max_records": max_records,
            "budget_tokens": budget_tokens,
        }))
        .send()
        .await?;
    emit_json_or_error(resp, "personal preferences clone replay suite").await
}
