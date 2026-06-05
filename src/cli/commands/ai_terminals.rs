use anyhow::{anyhow, Result};
use reqwest::Method;
use serde_json::json;

use crate::cli::http_client::CliHttpClient;

use super::emit_json_or_error;

pub(crate) async fn run(command: crate::cli::AiTerminalsCommand) -> Result<()> {
    match command {
        crate::cli::AiTerminalsCommand::Detect { all, terminals } => {
            run_detect(all, terminals).await
        }
        crate::cli::AiTerminalsCommand::List => run_list().await,
        crate::cli::AiTerminalsCommand::Status => run_status().await,
        crate::cli::AiTerminalsCommand::Events { limit, offset } => run_events(limit, offset).await,
        crate::cli::AiTerminalsCommand::Integrate { all, terminals } => {
            run_integrate(all, terminals).await
        }
        crate::cli::AiTerminalsCommand::Capture {
            terminal,
            integration_id,
            source_session_id,
            event_kind,
            repo_scope,
            agent_id,
            summary,
            transcript_text,
            metadata_json,
        } => {
            run_capture(
                terminal,
                integration_id,
                source_session_id,
                event_kind,
                repo_scope,
                agent_id,
                summary,
                transcript_text,
                metadata_json,
            )
            .await
        }
        crate::cli::AiTerminalsCommand::SyncSkills {
            min_confidence,
            min_support_count,
            include_sensitive,
            no_install,
            terminals,
        } => {
            run_sync_skills(
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

async fn run_detect(all: bool, terminals: Vec<String>) -> Result<()> {
    let client = CliHttpClient::new()?;
    let terminals = if all { Vec::new() } else { terminals };
    let resp = client
        .request(Method::POST, "/v1/ai-terminals/detect")
        .json(&json!({ "terminals": terminals }))
        .send()
        .await?;
    emit_json_or_error(resp, "ai terminal detection").await
}

async fn run_list() -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(Method::GET, "/v1/ai-terminals/integrations")
        .send()
        .await?;
    emit_json_or_error(resp, "ai terminal integrations").await
}

async fn run_status() -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(Method::GET, "/v1/ai-terminals/status")
        .send()
        .await?;
    emit_json_or_error(resp, "ai terminal status").await
}

async fn run_events(limit: usize, offset: usize) -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(Method::GET, "/v1/ai-terminals/events")
        .query(&[
            ("limit", limit.max(1).to_string()),
            ("offset", offset.to_string()),
        ])
        .send()
        .await?;
    emit_json_or_error(resp, "ai terminal events").await
}

async fn run_integrate(all: bool, terminals: Vec<String>) -> Result<()> {
    let client = CliHttpClient::new()?;
    let terminals = if all { Vec::new() } else { terminals };
    let resp = client
        .request(Method::POST, "/v1/ai-terminals/integrations/bootstrap")
        .json(&json!({ "terminals": terminals }))
        .send()
        .await?;
    emit_json_or_error(resp, "ai terminal integration bootstrap").await
}

#[allow(clippy::too_many_arguments)]
async fn run_capture(
    terminal: String,
    integration_id: Option<String>,
    source_session_id: Option<String>,
    event_kind: Option<String>,
    repo_scope: Option<String>,
    agent_id: Option<String>,
    summary: String,
    transcript_text: Option<String>,
    metadata_json: Option<String>,
) -> Result<()> {
    let metadata = parse_metadata_json(metadata_json.as_deref())?;
    let client = CliHttpClient::new()?;
    let resp = client
        .request(Method::POST, "/v1/ai-terminals/capture")
        .json(&json!({
            "terminal": terminal,
            "integration_id": integration_id,
            "source_session_id": source_session_id,
            "event_kind": event_kind,
            "repo_scope": repo_scope,
            "agent_id": agent_id,
            "summary": summary,
            "transcript_text": transcript_text,
            "metadata": metadata,
        }))
        .send()
        .await?;
    emit_json_or_error(resp, "ai terminal capture").await
}

async fn run_sync_skills(
    min_confidence: f32,
    min_support_count: usize,
    include_sensitive: bool,
    no_install: bool,
    terminals: Vec<String>,
) -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(Method::POST, "/v1/ai-terminals/sync-skills")
        .json(&json!({
            "min_confidence": min_confidence,
            "min_support_count": min_support_count,
            "include_sensitive": include_sensitive,
            "install": !no_install,
            "terminals": terminals,
        }))
        .send()
        .await?;
    emit_json_or_error(resp, "ai terminal skill sync").await
}

fn parse_metadata_json(value: Option<&str>) -> Result<serde_json::Value> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(json!({}));
    };
    serde_json::from_str(value).map_err(|err| anyhow!("invalid metadata JSON: {err}"))
}
