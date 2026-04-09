use anyhow::Result;
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
        crate::cli::PersonalPreferencesCommand::Process { limit } => run_process(limit).await,
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

async fn run_process(limit: Option<usize>) -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(Method::POST, "/v1/personal-preferences/process")
        .json(&json!({ "limit": limit }))
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
