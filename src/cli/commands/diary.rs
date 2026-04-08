use super::emit_json_or_error;
use crate::cli::http_client::CliHttpClient;
use crate::cli::ConversationScopeArgs;
use crate::error::{self, ERR_INVALID_ARGUMENT};
use anyhow::Result;
use reqwest::Method;
use serde_json::json;

pub(crate) async fn run(command: crate::cli::DiaryCommand) -> Result<()> {
    match command {
        crate::cli::DiaryCommand::Write {
            scope,
            agent_id,
            entry_type,
            source_session_id,
            content,
        } => run_write(scope, agent_id, entry_type, source_session_id, content).await,
        crate::cli::DiaryCommand::Read {
            scope,
            agent_id,
            limit,
            offset,
        } => run_read(scope, agent_id, limit, offset).await,
    }
}

async fn run_write(
    scope: ConversationScopeArgs,
    agent_id: Option<String>,
    entry_type: String,
    source_session_id: Option<String>,
    content: String,
) -> Result<()> {
    if content.trim().is_empty() {
        return Err(error::AppError::new(ERR_INVALID_ARGUMENT, "content must not be empty").into());
    }
    let client = CliHttpClient::new()?;
    client.ensure_conversation_scope(&scope).await?;
    let mut req = client
        .request(Method::POST, "/v1/diary/write")
        .json(&json!({
            "agent_id": agent_id,
            "entry_type": entry_type,
            "source_session_id": source_session_id,
            "content": content,
        }));
    req = client.with_conversation_scope(req, &scope)?;
    emit_json_or_error(req.send().await?, "diary write").await
}

async fn run_read(
    scope: ConversationScopeArgs,
    agent_id: Option<String>,
    limit: usize,
    offset: usize,
) -> Result<()> {
    if limit == 0 {
        return Err(
            error::AppError::new(ERR_INVALID_ARGUMENT, "limit must be greater than 0").into(),
        );
    }
    let client = CliHttpClient::new()?;
    client.ensure_conversation_scope(&scope).await?;
    let mut query = vec![("limit", limit.to_string()), ("offset", offset.to_string())];
    if let Some(agent_id) = agent_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        query.push(("agent_id", agent_id.to_string()));
    }
    let mut req = client.request(Method::GET, "/v1/diary/read").query(&query);
    req = client.with_conversation_scope(req, &scope)?;
    emit_json_or_error(req.send().await?, "diary read").await
}
