use anyhow::{anyhow, Result};
use reqwest::Method;
use serde_json::json;

use crate::cli::http_client::CliHttpClient;

use super::emit_json_or_error;

pub(crate) async fn run(command: crate::cli::PersonalPreferencesCommand) -> Result<()> {
    match command {
        crate::cli::PersonalPreferencesCommand::Status => run_status().await,
        crate::cli::PersonalPreferencesCommand::Categories => run_categories().await,
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
        crate::cli::PersonalPreferencesCommand::Snapshots { command } => {
            run_snapshots(command).await
        }
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
