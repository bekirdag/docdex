use super::emit_json_or_error;
use crate::cli::http_client::CliHttpClient;
use crate::cli::ConversationScopeArgs;
use crate::error::{self, ERR_INVALID_ARGUMENT};
use anyhow::Result;
use reqwest::Method;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

pub(crate) async fn run(command: crate::cli::ConversationCommand) -> Result<()> {
    match command {
        crate::cli::ConversationCommand::Import {
            scope,
            path,
            format,
            source,
            source_session_id,
            title,
            agent_id,
            transport,
        } => {
            run_import(
                scope,
                path,
                format,
                source,
                source_session_id,
                title,
                agent_id,
                transport,
            )
            .await
        }
        crate::cli::ConversationCommand::Search {
            scope,
            query,
            agent_id,
            limit,
            offset,
        } => run_search(scope, query, agent_id, limit, offset).await,
        crate::cli::ConversationCommand::List {
            scope,
            agent_id,
            limit,
            offset,
        } => run_list(scope, agent_id, limit, offset).await,
        crate::cli::ConversationCommand::Read { scope, session_id } => {
            run_read(scope, session_id).await
        }
        crate::cli::ConversationCommand::Export { scope, session_id } => {
            run_export(scope, session_id).await
        }
        crate::cli::ConversationCommand::Redact { scope, session_id } => {
            run_redact(scope, session_id).await
        }
        crate::cli::ConversationCommand::Prune {
            scope,
            apply,
            manual_retention_days,
            auto_capture_retention_days,
            diary_retention_days,
            hook_event_retention_days,
            working_memory_retention_days,
            episodic_rollup_retention_days,
        } => {
            run_prune(
                scope,
                apply,
                manual_retention_days,
                auto_capture_retention_days,
                diary_retention_days,
                hook_event_retention_days,
                working_memory_retention_days,
                episodic_rollup_retention_days,
            )
            .await
        }
        crate::cli::ConversationCommand::Delete { scope, session_id } => {
            run_delete(scope, session_id).await
        }
        crate::cli::ConversationCommand::KgQuery {
            scope,
            query,
            relation,
            limit,
            offset,
        } => run_kg_query(scope, query, relation, limit, offset).await,
        crate::cli::ConversationCommand::KgTimeline {
            scope,
            entity,
            relation,
            limit,
        } => run_kg_timeline(scope, entity, relation, limit).await,
        crate::cli::ConversationCommand::KgSearchNodes {
            scope,
            query,
            entity_type,
            limit,
            offset,
        } => run_kg_search_nodes(scope, query, entity_type, limit, offset).await,
        crate::cli::ConversationCommand::KgSearchEdges {
            scope,
            query,
            relation,
            limit,
            offset,
        } => run_kg_search_edges(scope, query, relation, limit, offset).await,
        crate::cli::ConversationCommand::KgSearchEpisodes {
            scope,
            query,
            source_type,
            limit,
            offset,
        } => run_kg_search_episodes(scope, query, source_type, limit, offset).await,
        crate::cli::ConversationCommand::KgNeighborhood {
            scope,
            entity,
            relation,
            limit,
        } => run_kg_neighborhood(scope, entity, relation, limit).await,
        crate::cli::ConversationCommand::KgEntityLinks {
            scope,
            entity,
            link_type,
            limit,
        } => run_kg_entity_links(scope, entity, link_type, limit).await,
        crate::cli::ConversationCommand::KgEpisode {
            scope,
            episode_id,
            limit,
        } => run_kg_episode(scope, episode_id, limit).await,
        crate::cli::ConversationCommand::KgDeleteEdge { scope, edge_id } => {
            run_kg_delete_edge(scope, edge_id).await
        }
        crate::cli::ConversationCommand::KgDeleteEpisode { scope, episode_id } => {
            run_kg_delete_episode(scope, episode_id).await
        }
        crate::cli::ConversationCommand::KgRebuild { scope } => run_kg_rebuild(scope).await,
        crate::cli::ConversationCommand::KgClear { scope } => run_kg_clear(scope).await,
    }
}

async fn send_scoped_request(
    scope: &ConversationScopeArgs,
    method: Method,
    path: &str,
    query_items: &[(String, String)],
    body: Option<Value>,
    label: &str,
) -> Result<()> {
    let client = CliHttpClient::new()?;
    client.ensure_conversation_scope(scope).await?;
    let mut req = client.request(method, path);
    if !query_items.is_empty() {
        req = req.query(query_items);
    }
    if let Some(body) = body {
        req = req.json(&body);
    }
    req = client.with_conversation_scope(req, scope)?;
    let resp = req.send().await?;
    emit_json_or_error(resp, label).await
}

async fn run_import(
    scope: ConversationScopeArgs,
    path: PathBuf,
    format: String,
    source: Option<String>,
    source_session_id: Option<String>,
    title: Option<String>,
    agent_id: Option<String>,
    transport: Option<String>,
) -> Result<()> {
    let transcript_text = fs::read_to_string(&path)?;
    let client = CliHttpClient::new()?;
    client.ensure_conversation_scope(&scope).await?;
    let mut req = client
        .request(Method::POST, "/v1/conversations/import")
        .json(&json!({
            "source": source,
            "source_session_id": source_session_id,
            "title": title,
            "agent_id": agent_id,
            "transport": transport,
            "format": format,
            "transcript_text": transcript_text,
            "metadata": {
                "import_path": path.display().to_string()
            }
        }));
    req = client.with_conversation_scope(req, &scope)?;
    let resp = req.send().await?;
    emit_json_or_error(resp, "conversation import").await
}

async fn run_search(
    scope: ConversationScopeArgs,
    query: String,
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
    let mut query_items = vec![
        ("q", query),
        ("limit", limit.to_string()),
        ("offset", offset.to_string()),
    ];
    if let Some(agent_id) = agent_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        query_items.push(("agent_id", agent_id.to_string()));
    }
    let mut req = client
        .request(Method::GET, "/v1/conversations/search")
        .query(&query_items);
    req = client.with_conversation_scope(req, &scope)?;
    let resp = req.send().await?;
    emit_json_or_error(resp, "conversation search").await
}

async fn run_list(
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
    let mut req = client
        .request(Method::GET, "/v1/conversations")
        .query(&query);
    req = client.with_conversation_scope(req, &scope)?;
    let resp = req.send().await?;
    emit_json_or_error(resp, "conversation list").await
}

async fn run_read(scope: ConversationScopeArgs, session_id: String) -> Result<()> {
    let client = CliHttpClient::new()?;
    client.ensure_conversation_scope(&scope).await?;
    let path = format!("/v1/conversations/{session_id}");
    let mut req = client.request(Method::GET, &path);
    req = client.with_conversation_scope(req, &scope)?;
    let resp = req.send().await?;
    emit_json_or_error(resp, "conversation read").await
}

async fn run_export(scope: ConversationScopeArgs, session_id: String) -> Result<()> {
    let client = CliHttpClient::new()?;
    client.ensure_conversation_scope(&scope).await?;
    let path = format!("/v1/conversations/{session_id}/export");
    let mut req = client.request(Method::GET, &path);
    req = client.with_conversation_scope(req, &scope)?;
    let resp = req.send().await?;
    emit_json_or_error(resp, "conversation export").await
}

async fn run_redact(scope: ConversationScopeArgs, session_id: String) -> Result<()> {
    let client = CliHttpClient::new()?;
    client.ensure_conversation_scope(&scope).await?;
    let path = format!("/v1/conversations/{session_id}/redact");
    let mut req = client.request(Method::POST, &path);
    req = client.with_conversation_scope(req, &scope)?;
    let resp = req.send().await?;
    emit_json_or_error(resp, "conversation redact").await
}

async fn run_prune(
    scope: ConversationScopeArgs,
    apply: bool,
    manual_retention_days: Option<u32>,
    auto_capture_retention_days: Option<u32>,
    diary_retention_days: Option<u32>,
    hook_event_retention_days: Option<u32>,
    working_memory_retention_days: Option<u32>,
    episodic_rollup_retention_days: Option<u32>,
) -> Result<()> {
    let client = CliHttpClient::new()?;
    client.ensure_conversation_scope(&scope).await?;
    let mut req = client
        .request(Method::POST, "/v1/conversations/prune")
        .json(&json!({
            "apply": apply,
            "manual_retention_days": manual_retention_days,
            "auto_capture_retention_days": auto_capture_retention_days,
            "diary_retention_days": diary_retention_days,
            "hook_event_retention_days": hook_event_retention_days,
            "working_memory_retention_days": working_memory_retention_days,
            "episodic_rollup_retention_days": episodic_rollup_retention_days,
        }));
    req = client.with_conversation_scope(req, &scope)?;
    let resp = req.send().await?;
    emit_json_or_error(resp, "conversation prune").await
}

async fn run_delete(scope: ConversationScopeArgs, session_id: String) -> Result<()> {
    let client = CliHttpClient::new()?;
    client.ensure_conversation_scope(&scope).await?;
    let path = format!("/v1/conversations/{session_id}");
    let mut req = client.request(Method::DELETE, &path);
    req = client.with_conversation_scope(req, &scope)?;
    let resp = req.send().await?;
    emit_json_or_error(resp, "conversation delete").await
}

async fn run_kg_query(
    scope: ConversationScopeArgs,
    query: String,
    relation: Option<String>,
    limit: usize,
    offset: usize,
) -> Result<()> {
    if limit == 0 {
        return Err(
            error::AppError::new(ERR_INVALID_ARGUMENT, "limit must be greater than 0").into(),
        );
    }
    let mut query_items = vec![
        ("q".to_string(), query),
        ("limit".to_string(), limit.to_string()),
        ("offset".to_string(), offset.to_string()),
    ];
    if let Some(relation) = relation
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        query_items.push(("relation".to_string(), relation.to_string()));
    }
    send_scoped_request(
        &scope,
        Method::GET,
        "/v1/kg/query",
        &query_items,
        None,
        "kg query",
    )
    .await
}

async fn run_kg_timeline(
    scope: ConversationScopeArgs,
    entity: String,
    relation: Option<String>,
    limit: usize,
) -> Result<()> {
    if limit == 0 {
        return Err(
            error::AppError::new(ERR_INVALID_ARGUMENT, "limit must be greater than 0").into(),
        );
    }
    let mut query_items = vec![
        ("entity".to_string(), entity),
        ("limit".to_string(), limit.to_string()),
    ];
    if let Some(relation) = relation
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        query_items.push(("relation".to_string(), relation.to_string()));
    }
    send_scoped_request(
        &scope,
        Method::GET,
        "/v1/kg/timeline",
        &query_items,
        None,
        "kg timeline",
    )
    .await
}

async fn run_kg_search_nodes(
    scope: ConversationScopeArgs,
    query: String,
    entity_type: Option<String>,
    limit: usize,
    offset: usize,
) -> Result<()> {
    ensure_positive_limit(limit)?;
    let mut query_items = vec![
        ("q".to_string(), query),
        ("limit".to_string(), limit.to_string()),
        ("offset".to_string(), offset.to_string()),
    ];
    if let Some(entity_type) = entity_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        query_items.push(("entity_type".to_string(), entity_type.to_string()));
    }
    send_scoped_request(
        &scope,
        Method::GET,
        "/v1/kg/search/nodes",
        &query_items,
        None,
        "kg node search",
    )
    .await
}

async fn run_kg_search_edges(
    scope: ConversationScopeArgs,
    query: String,
    relation: Option<String>,
    limit: usize,
    offset: usize,
) -> Result<()> {
    ensure_positive_limit(limit)?;
    let mut query_items = vec![
        ("q".to_string(), query),
        ("limit".to_string(), limit.to_string()),
        ("offset".to_string(), offset.to_string()),
    ];
    if let Some(relation) = relation
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        query_items.push(("relation".to_string(), relation.to_string()));
    }
    send_scoped_request(
        &scope,
        Method::GET,
        "/v1/kg/search/edges",
        &query_items,
        None,
        "kg edge search",
    )
    .await
}

async fn run_kg_search_episodes(
    scope: ConversationScopeArgs,
    query: String,
    source_type: Option<String>,
    limit: usize,
    offset: usize,
) -> Result<()> {
    ensure_positive_limit(limit)?;
    let mut query_items = vec![
        ("q".to_string(), query),
        ("limit".to_string(), limit.to_string()),
        ("offset".to_string(), offset.to_string()),
    ];
    if let Some(source_type) = source_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        query_items.push(("source_type".to_string(), source_type.to_string()));
    }
    send_scoped_request(
        &scope,
        Method::GET,
        "/v1/kg/search/episodes",
        &query_items,
        None,
        "kg episode search",
    )
    .await
}

async fn run_kg_neighborhood(
    scope: ConversationScopeArgs,
    entity: String,
    relation: Option<String>,
    limit: usize,
) -> Result<()> {
    ensure_positive_limit(limit)?;
    let mut query_items = vec![
        ("entity".to_string(), entity),
        ("limit".to_string(), limit.to_string()),
    ];
    if let Some(relation) = relation
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        query_items.push(("relation".to_string(), relation.to_string()));
    }
    send_scoped_request(
        &scope,
        Method::GET,
        "/v1/kg/neighborhood",
        &query_items,
        None,
        "kg neighborhood",
    )
    .await
}

async fn run_kg_entity_links(
    scope: ConversationScopeArgs,
    entity: String,
    link_type: Option<String>,
    limit: usize,
) -> Result<()> {
    ensure_positive_limit(limit)?;
    let mut query_items = vec![
        ("entity".to_string(), entity),
        ("limit".to_string(), limit.to_string()),
    ];
    if let Some(link_type) = link_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        query_items.push(("link_type".to_string(), link_type.to_string()));
    }
    send_scoped_request(
        &scope,
        Method::GET,
        "/v1/kg/entity-links",
        &query_items,
        None,
        "kg entity links",
    )
    .await
}

async fn run_kg_episode(
    scope: ConversationScopeArgs,
    episode_id: String,
    limit: usize,
) -> Result<()> {
    ensure_positive_limit(limit)?;
    let query_items = vec![
        ("episode_id".to_string(), episode_id),
        ("limit".to_string(), limit.to_string()),
    ];
    send_scoped_request(
        &scope,
        Method::GET,
        "/v1/kg/episode",
        &query_items,
        None,
        "kg episode",
    )
    .await
}

async fn run_kg_delete_edge(scope: ConversationScopeArgs, edge_id: String) -> Result<()> {
    send_scoped_request(
        &scope,
        Method::POST,
        "/v1/kg/edge/delete",
        &[],
        Some(json!({ "edge_id": edge_id })),
        "kg delete edge",
    )
    .await
}

async fn run_kg_delete_episode(scope: ConversationScopeArgs, episode_id: String) -> Result<()> {
    send_scoped_request(
        &scope,
        Method::POST,
        "/v1/kg/episode/delete",
        &[],
        Some(json!({ "episode_id": episode_id })),
        "kg delete episode",
    )
    .await
}

async fn run_kg_rebuild(scope: ConversationScopeArgs) -> Result<()> {
    send_scoped_request(
        &scope,
        Method::POST,
        "/v1/kg/rebuild",
        &[],
        Some(json!({})),
        "kg rebuild",
    )
    .await
}

async fn run_kg_clear(scope: ConversationScopeArgs) -> Result<()> {
    send_scoped_request(
        &scope,
        Method::POST,
        "/v1/kg/clear",
        &[],
        Some(json!({})),
        "kg clear",
    )
    .await
}

fn ensure_positive_limit(limit: usize) -> Result<()> {
    if limit == 0 {
        return Err(
            error::AppError::new(ERR_INVALID_ARGUMENT, "limit must be greater than 0").into(),
        );
    }
    Ok(())
}
