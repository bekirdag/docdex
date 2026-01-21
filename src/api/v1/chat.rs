use axum::body::{Body, Bytes};
use axum::extract::Query;
use axum::{
    extract::State,
    http::header::{CACHE_CONTROL, CONTENT_TYPE},
    http::HeaderMap,
    http::HeaderValue,
};
use axum::{http::StatusCode, Json};
use axum::{response::IntoResponse, response::Response};
use futures::stream;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::convert::Infallible;
use std::path::Path;
use std::time::Duration;
use uuid::Uuid;

use crate::dag::logging as dag_logging;
use crate::diff;
use crate::error::{AppError, ERR_INTERNAL_ERROR};
use crate::memory::repo_state_root_from_state_dir;
use crate::ollama::OllamaClient;
use crate::orchestrator::web::web_context_from_status;
use crate::orchestrator::{
    memory_budget_from_max_answer_tokens, run_waterfall, ProfileBudget, SymbolContextAssembly,
    WaterfallPlan, WaterfallRequest, WebGateConfig,
};
use crate::project_map;
use crate::search::{resolve_repo_context, status_for_app_error, AppState};
use crate::tier2::Tier2Config;
use tracing::{info, warn};

const DEFAULT_LIMIT: usize = 8;
const STREAM_CHUNK_CHARS: usize = 320;
const CHAT_GENERATION_TIMEOUT_SECS: u64 = 30;
const CHAT_SYSTEM_PROMPT: &str = "You are Docdex, a local-first assistant. Use the provided context when relevant. If the answer is not in the context, say so.";
const PROJECT_MAP_TOKEN_CAP: usize = 500;
const DAG_SESSION_HEADER: &str = "x-docdex-dag-session";

#[derive(Debug, Deserialize)]
pub(crate) struct ChatCompletionRequest {
    model: Option<String>,
    #[serde(default)]
    agent: Option<String>,
    messages: Vec<ChatMessage>,
    #[serde(default)]
    stream: bool,
    #[serde(default)]
    repo_id: Option<String>,
    #[serde(default)]
    docdex: Option<DocdexOptions>,
}

#[derive(Debug, Deserialize)]
struct DocdexOptions {
    limit: Option<usize>,
    force_web: Option<bool>,
    skip_local_search: Option<bool>,
    no_cache: Option<bool>,
    include_libs: Option<bool>,
    max_web_results: Option<usize>,
    llm_filter_local_results: Option<bool>,
    compress_results: Option<bool>,
    agent_id: Option<String>,
    #[serde(alias = "session_id", alias = "dagSessionId")]
    dag_session_id: Option<String>,
    diff: Option<diff::DiffOptions>,
}

#[derive(Debug, Deserialize)]
struct ChatMessage {
    role: String,
    content: MessageContent,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum MessageContent {
    Text(String),
    Parts(Vec<MessagePart>),
    Other(serde_json::Value),
}

#[derive(Debug, Deserialize)]
struct MessagePart {
    #[serde(rename = "type")]
    part_type: Option<String>,
    text: Option<String>,
}

#[derive(Serialize)]
struct ChatCompletionResponse {
    id: String,
    object: &'static str,
    created: u64,
    model: String,
    choices: Vec<ChatChoice>,
    usage: Usage,
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning_trace: Option<ReasoningTrace>,
}

#[derive(Serialize)]
struct ChatChoice {
    index: u32,
    message: ChatMessageResponse,
    finish_reason: &'static str,
}

#[derive(Serialize)]
struct ChatMessageResponse {
    role: &'static str,
    content: String,
}

#[derive(Serialize)]
struct Usage {
    prompt_tokens: u64,
    completion_tokens: u64,
    total_tokens: u64,
}

#[derive(Clone, Serialize)]
struct ReasoningTrace {
    behavioral_truth: BehavioralTruth,
    technical_truth: TechnicalTruth,
}

#[derive(Clone, Serialize)]
struct BehavioralTruth {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    style: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    workflow: Vec<String>,
}

#[derive(Clone, Serialize)]
struct TechnicalTruth {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    memory: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    repo: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    web: Vec<String>,
}

#[derive(Serialize)]
struct ChatCompletionChunk {
    id: String,
    object: &'static str,
    created: u64,
    model: String,
    choices: Vec<ChatChunkChoice>,
}

#[derive(Serialize)]
struct ChatChunkChoice {
    index: u32,
    delta: ChatChunkDelta,
    #[serde(skip_serializing_if = "Option::is_none")]
    finish_reason: Option<&'static str>,
}

#[derive(Serialize)]
struct ChatChunkDelta {
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
}

#[derive(Serialize)]
struct OpenAiErrorResponse {
    error: OpenAiErrorDetail,
}

#[derive(Serialize)]
struct OpenAiErrorDetail {
    message: String,
    #[serde(rename = "type")]
    error_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'static str>,
}

#[derive(Deserialize)]
pub(crate) struct RepoIdQuery {
    #[serde(default)]
    repo_id: Option<String>,
}

pub fn resolve_profile_agent_id(
    header_value: Option<&str>,
    body_value: Option<&str>,
) -> Option<String> {
    let header = header_value
        .map(|value| value.trim())
        .filter(|value| !value.is_empty());
    let body = body_value
        .map(|value| value.trim())
        .filter(|value| !value.is_empty());
    header.or(body).map(str::to_string)
}

fn header_dag_session_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get(DAG_SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

pub(crate) async fn chat_completions_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(repo_id): Query<RepoIdQuery>,
    Json(payload): Json<ChatCompletionRequest>,
) -> Response {
    let repo = match resolve_repo_context(
        &state,
        &headers,
        repo_id.repo_id.as_deref(),
        payload.repo_id.as_deref(),
        false,
    ) {
        Ok(repo) => repo,
        Err(err) => {
            return error_response(err.status, "invalid_request_error", err.code, &err.message);
        }
    };
    if let Err(err) = crate::index::ensure_indexed(repo.indexer.clone()).await {
        state.metrics.inc_error();
        if let Some(app) = err.downcast_ref::<AppError>() {
            return error_response(
                status_for_app_error(app.code),
                "server_error",
                app.code,
                &app.message,
            );
        }
        warn!(target: "docdexd", error = ?err, "indexing failed");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            ERR_INTERNAL_ERROR,
            "indexing failed",
        );
    }
    let extracted = match extract_query_and_context(&payload.messages) {
        Some(value) => value,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                "missing_query",
                "messages must include a user message",
            );
        }
    };
    let query = extracted.query;
    if query.trim().is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            "invalid_query",
            "user message content must not be empty",
        );
    }
    if state.security.max_query_bytes > 0 && query.len() > state.security.max_query_bytes {
        return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "invalid_request_error",
            "query_too_large",
            "user message exceeds max_query_bytes",
        );
    }

    let docdex = payload.docdex.as_ref();
    let header_agent_id = headers
        .get("x-docdex-agent-id")
        .and_then(|value| value.to_str().ok());
    let header_dag_session_id = header_dag_session_id(&headers);
    let body_agent_id = docdex.and_then(|opts| opts.agent_id.as_deref());
    let body_dag_session_id = docdex.and_then(|opts| opts.dag_session_id.as_deref());
    let profile_agent_id = resolve_profile_agent_id(header_agent_id, body_agent_id)
        .or_else(|| state.default_agent_id.clone());
    let limit = docdex
        .and_then(|opts| opts.limit)
        .unwrap_or(DEFAULT_LIMIT)
        .min(state.security.max_limit);
    let max_web_results = docdex.and_then(|opts| opts.max_web_results);
    let force_web = docdex.and_then(|opts| opts.force_web).unwrap_or(false);
    let skip_local_search = docdex
        .and_then(|opts| opts.skip_local_search)
        .unwrap_or(false);
    let disable_web_cache = docdex.and_then(|opts| opts.no_cache).unwrap_or(false);
    let include_libs = docdex.and_then(|opts| opts.include_libs).unwrap_or(true);
    let llm_filter_local_results = docdex
        .and_then(|opts| opts.llm_filter_local_results)
        .unwrap_or(false);
    let compress_results = docdex
        .and_then(|opts| opts.compress_results)
        .unwrap_or(false);
    let diff_request =
        match diff::resolve_diff_request_from_options(docdex.and_then(|opts| opts.diff.as_ref())) {
            Ok(value) => value,
            Err(err) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request_error",
                    "invalid_diff",
                    &err.to_string(),
                );
            }
        };
    let libs_indexer = if include_libs {
        repo.libs_indexer.as_deref()
    } else {
        None
    };

    let plan = WaterfallPlan::new(
        WebGateConfig::from_env(),
        Tier2Config::enabled(),
        memory_budget_from_max_answer_tokens(state.max_answer_tokens),
        ProfileBudget::default(),
    );
    let request_id = Uuid::new_v4().to_string();
    let repo_state_root = repo_state_root_from_state_dir(repo.indexer.state_dir());
    let dag_session_id = header_dag_session_id
        .as_deref()
        .or(body_dag_session_id)
        .unwrap_or(request_id.as_str())
        .to_string();
    queue_dag_log(
        repo_state_root.clone(),
        dag_session_id.clone(),
        "UserRequest",
        json!({
            "query": query.clone(),
            "context": extracted.context.clone(),
            "force_web": force_web,
            "skip_local_search": skip_local_search,
            "max_web_results": max_web_results,
            "limit": limit,
            "agent_id": profile_agent_id.as_deref(),
            "diff": docdex.and_then(|opts| opts.diff.as_ref()).map(|opts| json!(opts)),
        }),
    );
    let query_with_context = if extracted.context.trim().is_empty() {
        query.clone()
    } else {
        format!("{}\n\nUser:\n{}", extracted.context, query)
    };
    let response = match run_waterfall(WaterfallRequest {
        request_id: &request_id,
        dag_session_id: Some(dag_session_id.as_str()),
        query: &query_with_context,
        limit,
        diff: diff_request,
        web_limit: max_web_results,
        force_web,
        skip_local_search,
        disable_web_cache,
        llm_filter_local_results,
        llm_model: payload.model.as_deref(),
        llm_agent: payload.agent.as_deref(),
        indexer: repo.indexer.as_ref(),
        libs_indexer,
        plan,
        tier2_limiter: None,
        memory: repo.memory.as_ref(),
        profile_state: state.profile_state.as_ref(),
        profile_agent_id: profile_agent_id.as_deref(),
        ranking_surface: crate::search::RankingSurface::Chat,
    })
    .await
    {
        Ok(result) => {
            let result = result;
            let budgets = chat_context_budgets(state.max_answer_tokens);
            let web_context = web_context_from_status(&result.tier2.status);
            let created = now_epoch_seconds();
            let mut model = payload
                .model
                .clone()
                .unwrap_or_else(|| state.llm_default_model.clone());
            let project_map = if compress_results || !state.features.project_map {
                None
            } else {
                match (profile_agent_id.as_deref(), state.profile_state.as_ref()) {
                    (Some(agent_id), Some(profile_state)) => {
                        project_map::load_cached_project_map(repo.indexer.state_dir(), agent_id)
                            .or_else(|| {
                                match project_map::build_project_map(
                                    repo.indexer.as_ref(),
                                    &profile_state.manager,
                                    agent_id,
                                ) {
                                    Ok(map) => {
                                        if let Err(err) = project_map::write_project_map_cache(
                                            repo.indexer.state_dir(),
                                            &map,
                                        ) {
                                            warn!(
                                                target: "docdexd",
                                                error = ?err,
                                                "project map cache write failed"
                                            );
                                        }
                                        Some(map)
                                    }
                                    Err(err) => {
                                        warn!(
                                            target: "docdexd",
                                            error = ?err,
                                            "project map build failed"
                                        );
                                        None
                                    }
                                }
                            })
                    }
                    _ => None,
                }
            };
            let reasoning_trace = build_reasoning_trace(
                result.profile_context.as_ref(),
                result.memory_context.as_ref(),
                &result.search_response.hits,
                web_context.as_deref(),
            );
            if let Some(trace) = reasoning_trace.as_ref() {
                queue_dag_log(
                    repo_state_root.clone(),
                    dag_session_id.clone(),
                    "ReasoningTrace",
                    json!({
                        "behavioral_truth": {
                            "style": trace.behavioral_truth.style.clone(),
                            "workflow": trace.behavioral_truth.workflow.clone(),
                        },
                        "technical_truth": {
                            "memory": trace.technical_truth.memory.clone(),
                            "repo": trace.technical_truth.repo.clone(),
                            "web": trace.technical_truth.web.clone(),
                        }
                    }),
                );
            }

            if compress_results {
                if model.trim().is_empty() {
                    model = "docdex".to_string();
                }
                let content = format_compressed_results(
                    &result.search_response.hits,
                    result.search_response.symbols_context.as_ref(),
                    web_context.as_deref(),
                    result.profile_context.as_ref(),
                    result.memory_context.as_ref(),
                    result.impact_context.as_ref(),
                    &budgets,
                );
                let prompt_tokens = estimate_tokens(&query);
                let completion_tokens = estimate_tokens(&content);
                let usage = Usage {
                    prompt_tokens,
                    completion_tokens,
                    total_tokens: prompt_tokens + completion_tokens,
                };
                queue_dag_log(
                    repo_state_root.clone(),
                    dag_session_id.clone(),
                    "Decision",
                    json!({
                        "model": model.clone(),
                        "compressed": true,
                        "response_chars": content.len(),
                    }),
                );
                if payload.stream {
                    let id = format!("chatcmpl-{}", request_id);
                    let mut content_chunks = chunk_text(&content, STREAM_CHUNK_CHARS);
                    if content_chunks.is_empty() {
                        content_chunks.push(String::new());
                    }
                    let chunk_id = id.clone();
                    let chunk_model = model.clone();
                    let chunk_created = created;
                    let content_iter =
                        content_chunks
                            .into_iter()
                            .enumerate()
                            .map(move |(idx, piece)| {
                                let role = if idx == 0 { Some("assistant") } else { None };
                                ChatCompletionChunk {
                                    id: chunk_id.clone(),
                                    object: "chat.completion.chunk",
                                    created: chunk_created,
                                    model: chunk_model.clone(),
                                    choices: vec![ChatChunkChoice {
                                        index: 0,
                                        delta: ChatChunkDelta {
                                            role,
                                            content: Some(piece),
                                        },
                                        finish_reason: None,
                                    }],
                                }
                            });
                    let final_chunk = ChatCompletionChunk {
                        id,
                        object: "chat.completion.chunk",
                        created,
                        model,
                        choices: vec![ChatChunkChoice {
                            index: 0,
                            delta: ChatChunkDelta {
                                role: None,
                                content: None,
                            },
                            finish_reason: Some("stop"),
                        }],
                    };
                    return stream_response(content_iter.chain(std::iter::once(final_chunk)));
                }

                ChatCompletionResponse {
                    id: format!("chatcmpl-{}", request_id),
                    object: "chat.completion",
                    created,
                    model,
                    choices: vec![ChatChoice {
                        index: 0,
                        message: ChatMessageResponse {
                            role: "assistant",
                            content,
                        },
                        finish_reason: "stop",
                    }],
                    usage,
                    reasoning_trace: reasoning_trace.clone(),
                }
            } else {
                if model.trim().is_empty() {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "invalid_request_error",
                        "missing_model",
                        "model must be specified when no default_model is configured",
                    );
                }
                let (context, context_trace) = build_context_summary(
                    &query,
                    &result.search_response.hits,
                    result.search_response.symbols_context.as_ref(),
                    web_context.as_deref(),
                    result.profile_context.as_ref(),
                    project_map.as_ref(),
                    state.features.workflow_prompt,
                    result.memory_context.as_ref(),
                    result.impact_context.as_ref(),
                    &budgets,
                );
                log_budget_drops(&request_id, repo.indexer.repo_root(), &context_trace);
                let history_budget = budgets
                    .history_tokens
                    .saturating_add(context_trace.repo_unused_tokens);
                let prompt = build_prompt(
                    &query,
                    &context,
                    &extracted.history,
                    history_budget,
                    &budgets,
                );
                let client = match OllamaClient::new(state.llm_base_url.clone()) {
                    Ok(client) => client,
                    Err(err) => {
                        return error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "server_error",
                            "ollama_config_error",
                            &err.to_string(),
                        );
                    }
                };
                let completion = match client
                    .generate(
                        &model,
                        &prompt,
                        state.max_answer_tokens,
                        Duration::from_secs(CHAT_GENERATION_TIMEOUT_SECS),
                    )
                    .await
                {
                    Ok(output) => output,
                    Err(err) => {
                        return error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "server_error",
                            "llm_generate_failed",
                            &err.to_string(),
                        );
                    }
                };
                let prompt_tokens = estimate_tokens(&prompt);
                let completion_tokens = estimate_tokens(&completion);
                let usage = Usage {
                    prompt_tokens,
                    completion_tokens,
                    total_tokens: prompt_tokens + completion_tokens,
                };
                queue_dag_log(
                    repo_state_root.clone(),
                    dag_session_id.clone(),
                    "Decision",
                    json!({
                        "model": model.clone(),
                        "compressed": false,
                        "response_chars": completion.len(),
                    }),
                );
                if payload.stream {
                    let id = format!("chatcmpl-{}", request_id);
                    let mut content_chunks = chunk_text(&completion, STREAM_CHUNK_CHARS);
                    if content_chunks.is_empty() {
                        content_chunks.push(String::new());
                    }
                    let chunk_id = id.clone();
                    let chunk_model = model.clone();
                    let chunk_created = created;
                    let content_iter =
                        content_chunks
                            .into_iter()
                            .enumerate()
                            .map(move |(idx, piece)| {
                                let role = if idx == 0 { Some("assistant") } else { None };
                                ChatCompletionChunk {
                                    id: chunk_id.clone(),
                                    object: "chat.completion.chunk",
                                    created: chunk_created,
                                    model: chunk_model.clone(),
                                    choices: vec![ChatChunkChoice {
                                        index: 0,
                                        delta: ChatChunkDelta {
                                            role,
                                            content: Some(piece),
                                        },
                                        finish_reason: None,
                                    }],
                                }
                            });
                    let final_chunk = ChatCompletionChunk {
                        id,
                        object: "chat.completion.chunk",
                        created,
                        model,
                        choices: vec![ChatChunkChoice {
                            index: 0,
                            delta: ChatChunkDelta {
                                role: None,
                                content: None,
                            },
                            finish_reason: Some("stop"),
                        }],
                    };
                    return stream_response(content_iter.chain(std::iter::once(final_chunk)));
                }

                ChatCompletionResponse {
                    id: format!("chatcmpl-{}", request_id),
                    object: "chat.completion",
                    created,
                    model,
                    choices: vec![ChatChoice {
                        index: 0,
                        message: ChatMessageResponse {
                            role: "assistant",
                            content: completion,
                        },
                        finish_reason: "stop",
                    }],
                    usage,
                    reasoning_trace: reasoning_trace.clone(),
                }
            }
        }
        Err(err) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "internal_error",
                &err.to_string(),
            );
        }
    };

    (StatusCode::OK, Json(response)).into_response()
}

struct ChatQueryContext {
    query: String,
    context: String,
    history: String,
}

fn extract_query_and_context(messages: &[ChatMessage]) -> Option<ChatQueryContext> {
    let mut context_parts: Vec<String> = Vec::new();
    let mut history_parts: Vec<(String, String)> = Vec::new();
    let mut last_user: Option<String> = None;
    let mut last_user_index: Option<usize> = None;

    for message in messages {
        let role = message.role.to_ascii_lowercase();
        if role != "system" && role != "assistant" && role != "user" {
            continue;
        }
        let Some(text) = extract_message_text(&message.content) else {
            continue;
        };
        let trimmed = text.trim();
        if trimmed.is_empty() {
            continue;
        }
        context_parts.push(trimmed.to_string());
        if role == "user" || role == "assistant" {
            if role == "user" {
                last_user = Some(trimmed.to_string());
                last_user_index = Some(history_parts.len());
            }
            history_parts.push((role, trimmed.to_string()));
        }
    }

    let query = last_user?;
    let context = context_parts.join("\n\n");
    let history = build_history_from_messages(&history_parts, last_user_index);
    Some(ChatQueryContext {
        query,
        context,
        history,
    })
}

fn build_history_from_messages(
    history_parts: &[(String, String)],
    skip_index: Option<usize>,
) -> String {
    let mut lines = Vec::new();
    for (idx, (role, content)) in history_parts.iter().enumerate() {
        if Some(idx) == skip_index {
            continue;
        }
        let label = if role.eq_ignore_ascii_case("assistant") {
            "Assistant"
        } else {
            "User"
        };
        lines.push(format!("{label}: {content}"));
    }
    lines.join("\n")
}

fn extract_message_text(content: &MessageContent) -> Option<String> {
    match content {
        MessageContent::Text(text) => Some(text.trim().to_string()),
        MessageContent::Parts(parts) => {
            let mut out = Vec::new();
            for part in parts {
                let kind = part
                    .part_type
                    .as_deref()
                    .unwrap_or("text")
                    .to_ascii_lowercase();
                if kind != "text" && kind != "input_text" {
                    continue;
                }
                if let Some(text) = part.text.as_ref() {
                    if !text.trim().is_empty() {
                        out.push(text.trim().to_string());
                    }
                }
            }
            if out.is_empty() {
                None
            } else {
                Some(out.join("\n"))
            }
        }
        MessageContent::Other(value) => value.as_str().map(|text| text.trim().to_string()),
    }
}

struct ChatContextBudgets {
    system_tokens: usize,
    profile_tokens: usize,
    map_tokens: usize,
    memory_tokens: usize,
    diff_tokens: usize,
    repo_tokens: usize,
    history_tokens: usize,
}

struct ProfileSnippet {
    content: String,
    score: f32,
    category: crate::profiles::PreferenceCategory,
}

struct ProfileSnippetTrace {
    available: usize,
    selected: usize,
    truncated: usize,
    budget_tokens: usize,
    used_tokens: usize,
}

struct MapSnippetTrace {
    available: usize,
    selected: usize,
    truncated: usize,
    budget_tokens: usize,
}

struct MemorySnippet {
    content: String,
    score: f32,
}

struct MemorySnippetTrace {
    available: usize,
    selected: usize,
    truncated: usize,
    budget_tokens: usize,
}

struct RepoContextTrace {
    candidates: usize,
    selected: usize,
    budget_tokens: usize,
    budget_exhausted: bool,
}

struct DiffContextTrace {
    candidates: usize,
    selected: usize,
    budget_tokens: usize,
    budget_exhausted: bool,
}

struct WebContextTrace {
    candidates: usize,
    selected: usize,
    budget_tokens: usize,
    budget_exhausted: bool,
}

struct ChatContextTrace {
    profile: ProfileSnippetTrace,
    map: MapSnippetTrace,
    memory: MemorySnippetTrace,
    diff: DiffContextTrace,
    repo: RepoContextTrace,
    symbols: SymbolContextTrace,
    web: WebContextTrace,
    repo_unused_tokens: usize,
}

struct SymbolContextTrace {
    candidates: usize,
    selected: usize,
    budget_tokens: usize,
    budget_exhausted: bool,
}

fn chat_context_budgets(max_answer_tokens: u32) -> ChatContextBudgets {
    let generation_tokens = max_answer_tokens.max(1) as usize;
    let total_tokens = generation_tokens.saturating_mul(5);
    let system_tokens = total_tokens / 10;
    let memory_tokens = total_tokens / 5;
    let diff_tokens = total_tokens / 10;
    let history_tokens = 0;
    let profile_cap = ProfileBudget::default().token_budget;
    let base_used =
        system_tokens + memory_tokens + diff_tokens + generation_tokens + history_tokens;
    let remaining = total_tokens.saturating_sub(base_used);
    let repo_floor = (total_tokens / 5).max(1);
    let reserved_for_repo = repo_floor.min(remaining);
    let max_non_repo = remaining.saturating_sub(reserved_for_repo);
    let profile_tokens = profile_cap.min(max_non_repo);
    let map_tokens = PROJECT_MAP_TOKEN_CAP.min(max_non_repo.saturating_sub(profile_tokens));
    let repo_tokens = remaining.saturating_sub(profile_tokens + map_tokens);
    ChatContextBudgets {
        system_tokens,
        profile_tokens,
        map_tokens,
        memory_tokens,
        diff_tokens,
        repo_tokens,
        history_tokens,
    }
}

fn select_memory_snippets(
    memory_context: Option<&crate::orchestrator::MemoryContextAssembly>,
    budget_tokens: usize,
) -> (Vec<MemorySnippet>, MemorySnippetTrace) {
    let Some(context) = memory_context else {
        return (
            Vec::new(),
            MemorySnippetTrace {
                available: 0,
                selected: 0,
                truncated: 0,
                budget_tokens,
            },
        );
    };
    let available = context.items.len();
    let mut remaining = budget_tokens;
    let mut snippets = Vec::new();
    let mut truncated_count = 0usize;
    for item in &context.items {
        if remaining == 0 {
            break;
        }
        let item_tokens = item.token_estimate;
        if item_tokens <= remaining {
            snippets.push(MemorySnippet {
                content: item.content.clone(),
                score: item.score,
            });
            remaining = remaining.saturating_sub(item_tokens);
        } else {
            let (truncated_content, _used_tokens) = truncate_to_tokens(&item.content, remaining);
            if truncated_content.is_empty() {
                break;
            }
            snippets.push(MemorySnippet {
                content: truncated_content,
                score: item.score,
            });
            truncated_count += 1;
            break;
        }
    }
    let selected = snippets.len();
    (
        snippets,
        MemorySnippetTrace {
            available,
            selected,
            truncated: truncated_count,
            budget_tokens,
        },
    )
}

fn select_profile_snippets(
    profile_context: Option<&crate::orchestrator::ProfileContextAssembly>,
    budget_tokens: usize,
    allowed_categories: Option<&[crate::profiles::PreferenceCategory]>,
) -> (Vec<ProfileSnippet>, ProfileSnippetTrace) {
    let Some(context) = profile_context else {
        return (
            Vec::new(),
            ProfileSnippetTrace {
                available: 0,
                selected: 0,
                truncated: 0,
                budget_tokens,
                used_tokens: 0,
            },
        );
    };
    let filtered: Vec<&crate::profiles::ProfileContextItem> = context
        .items
        .iter()
        .filter(|item| {
            allowed_categories
                .map(|allowed| allowed.contains(&item.category))
                .unwrap_or(true)
        })
        .collect();
    let available = filtered.len();
    let mut remaining = budget_tokens;
    let mut snippets = Vec::new();
    let mut truncated_count = 0usize;
    for item in filtered {
        if remaining == 0 {
            break;
        }
        let item_tokens = item.token_estimate;
        if item_tokens <= remaining {
            snippets.push(ProfileSnippet {
                content: item.content.clone(),
                score: item.score,
                category: item.category.clone(),
            });
            remaining = remaining.saturating_sub(item_tokens);
        } else {
            let (truncated_content, _used_tokens) = truncate_to_tokens(&item.content, remaining);
            if truncated_content.is_empty() {
                break;
            }
            snippets.push(ProfileSnippet {
                content: truncated_content,
                score: item.score,
                category: item.category.clone(),
            });
            truncated_count += 1;
            break;
        }
    }
    let selected = snippets.len();
    (
        snippets,
        ProfileSnippetTrace {
            available,
            selected,
            truncated: truncated_count,
            budget_tokens,
            used_tokens: budget_tokens.saturating_sub(remaining),
        },
    )
}

fn select_project_map_snippet(
    map: Option<&project_map::ProjectMap>,
    budget_tokens: usize,
) -> (Option<String>, MapSnippetTrace) {
    let Some(map) = map else {
        return (
            None,
            MapSnippetTrace {
                available: 0,
                selected: 0,
                truncated: 0,
                budget_tokens,
            },
        );
    };
    if map.nodes.is_empty() || budget_tokens == 0 {
        return (
            None,
            MapSnippetTrace {
                available: 0,
                selected: 0,
                truncated: 0,
                budget_tokens,
            },
        );
    }
    let rendered = project_map::render_project_map(map);
    let estimated_tokens = estimate_tokens(&rendered) as usize;
    let (snippet, _) = truncate_to_tokens(&rendered, budget_tokens);
    let selected = if snippet.is_empty() { 0 } else { 1 };
    let truncated = if selected == 1 && estimated_tokens > budget_tokens {
        1
    } else {
        0
    };
    (
        if snippet.is_empty() {
            None
        } else {
            Some(snippet)
        },
        MapSnippetTrace {
            available: 1,
            selected,
            truncated,
            budget_tokens,
        },
    )
}

fn format_diff_context_with_budget(
    impact_context: &crate::impact::ImpactContextAssembly,
    budget_tokens: usize,
) -> (Vec<String>, DiffContextTrace) {
    let candidates = impact_context.sources.len() + impact_context.expanded_files.len();
    let mut lines = Vec::new();
    let mut remaining = budget_tokens;
    let mut selected = 0usize;
    let mut budget_exhausted = false;

    for source in &impact_context.sources {
        if remaining == 0 {
            budget_exhausted = true;
            break;
        }
        let line = format!("- changed: {source}");
        let tokens = estimate_tokens(&line) as usize;
        if tokens > remaining {
            budget_exhausted = true;
            break;
        }
        lines.push(line);
        selected += 1;
        remaining = remaining.saturating_sub(tokens);
    }

    if !budget_exhausted {
        for file in &impact_context.expanded_files {
            if remaining == 0 {
                budget_exhausted = true;
                break;
            }
            let line = format!("- related: {file}");
            let tokens = estimate_tokens(&line) as usize;
            if tokens > remaining {
                budget_exhausted = true;
                break;
            }
            lines.push(line);
            selected += 1;
            remaining = remaining.saturating_sub(tokens);
        }
    }

    (
        lines,
        DiffContextTrace {
            candidates,
            selected,
            budget_tokens,
            budget_exhausted,
        },
    )
}

fn build_context_summary(
    query: &str,
    hits: &[crate::index::Hit],
    symbols_context: Option<&SymbolContextAssembly>,
    web_context: Option<&[crate::orchestrator::web::WebFetchResult]>,
    profile_context: Option<&crate::orchestrator::ProfileContextAssembly>,
    project_map: Option<&project_map::ProjectMap>,
    include_workflow: bool,
    memory_context: Option<&crate::orchestrator::MemoryContextAssembly>,
    impact_context: Option<&crate::impact::ImpactContextAssembly>,
    budgets: &ChatContextBudgets,
) -> (String, ChatContextTrace) {
    let mut lines = Vec::new();
    let trimmed = query.trim();

    let style_categories = [crate::profiles::PreferenceCategory::Style];
    let (profile_snippets, profile_trace) = select_profile_snippets(
        profile_context,
        budgets.profile_tokens,
        Some(&style_categories),
    );
    if !profile_snippets.is_empty() {
        lines.push("Style preferences (advisory):".to_string());
        for snippet in profile_snippets {
            lines.push(format!("- {}", snippet.content));
        }
    }

    if include_workflow {
        let workflow_categories = [crate::profiles::PreferenceCategory::Workflow];
        let workflow_budget = budgets
            .profile_tokens
            .saturating_sub(profile_trace.used_tokens);
        let (workflow_snippets, _workflow_trace) =
            select_profile_snippets(profile_context, workflow_budget, Some(&workflow_categories));
        if !workflow_snippets.is_empty() {
            lines.push("Workflow guidance (advisory):".to_string());
            for snippet in workflow_snippets {
                lines.push(format!("- {}", snippet.content));
            }
        }
    }

    let (map_snippet, map_trace) = select_project_map_snippet(project_map, budgets.map_tokens);
    if let Some(snippet) = map_snippet {
        for line in snippet.lines() {
            lines.push(line.to_string());
        }
    }

    let (memory_snippets, memory_trace) =
        select_memory_snippets(memory_context, budgets.memory_tokens);
    if !memory_snippets.is_empty() {
        lines.push("Memory context:".to_string());
        for snippet in memory_snippets {
            lines.push(format!("- {}", snippet.content));
        }
    }

    let (diff_lines, diff_trace) = if let Some(context) = impact_context {
        format_diff_context_with_budget(context, budgets.diff_tokens)
    } else {
        (
            Vec::new(),
            DiffContextTrace {
                candidates: 0,
                selected: 0,
                budget_tokens: budgets.diff_tokens,
                budget_exhausted: false,
            },
        )
    };
    if !diff_lines.is_empty() {
        if !lines.is_empty() {
            lines.push(String::new());
        }
        lines.push("Diff context:".to_string());
        lines.extend(diff_lines);
    }

    let mut repo_remaining = budgets.repo_tokens;
    let repo_candidates = hits.iter().take(5).count();
    let mut repo_selected = 0usize;
    let mut repo_budget_exhausted = false;
    if repo_remaining > 0 {
        if !lines.is_empty() {
            lines.push(String::new());
        }
        if hits.is_empty() {
            let line = format!("No local documents matched query: {}", trimmed);
            let line_tokens = estimate_tokens(&line) as usize;
            if line_tokens <= repo_remaining {
                lines.push(line);
                repo_remaining = repo_remaining.saturating_sub(line_tokens);
            } else {
                repo_budget_exhausted = true;
            }
        } else {
            let header = if trimmed.is_empty() {
                "Top local matches:".to_string()
            } else {
                format!("Top local matches for query: {}", trimmed)
            };
            let header_tokens = estimate_tokens(&header) as usize;
            if header_tokens <= repo_remaining {
                lines.push(header);
                repo_remaining = repo_remaining.saturating_sub(header_tokens);
            } else {
                repo_remaining = 0;
                repo_budget_exhausted = true;
            }
            for hit in hits.iter().take(5) {
                if repo_remaining == 0 {
                    repo_budget_exhausted = true;
                    break;
                }
                let summary = hit.summary.trim();
                if summary.is_empty() {
                    let line = format!("- {}", hit.rel_path);
                    let line_tokens = estimate_tokens(&line) as usize;
                    if line_tokens > repo_remaining {
                        repo_budget_exhausted = true;
                        break;
                    }
                    lines.push(line);
                    repo_selected += 1;
                    repo_remaining = repo_remaining.saturating_sub(line_tokens);
                    continue;
                }
                let prefix = format!("- {}: ", hit.rel_path);
                let prefix_tokens = estimate_tokens(&prefix) as usize;
                if prefix_tokens >= repo_remaining {
                    repo_budget_exhausted = true;
                    break;
                }
                let available = repo_remaining - prefix_tokens;
                let (snippet, used_tokens) = truncate_to_tokens(summary, available);
                if snippet.is_empty() {
                    repo_budget_exhausted = true;
                    break;
                }
                lines.push(format!("{prefix}{snippet}"));
                repo_selected += 1;
                repo_remaining = repo_remaining.saturating_sub(prefix_tokens + used_tokens);
            }
        }
    }

    let (symbol_lines, symbol_trace, repo_remaining) =
        if let Some(symbols_context) = symbols_context {
            format_symbol_context_with_budget(symbols_context, repo_remaining)
        } else {
            (
                Vec::new(),
                SymbolContextTrace {
                    candidates: 0,
                    selected: 0,
                    budget_tokens: repo_remaining,
                    budget_exhausted: false,
                },
                repo_remaining,
            )
        };
    if !symbol_lines.is_empty() {
        if !lines.is_empty() {
            lines.push(String::new());
        }
        lines.push("Symbols context:".to_string());
        lines.extend(symbol_lines);
    }

    let (web_lines, web_trace, repo_remaining) = if let Some(web_context) = web_context {
        format_web_context_with_budget(web_context, repo_remaining)
    } else {
        (
            Vec::new(),
            WebContextTrace {
                candidates: 0,
                selected: 0,
                budget_tokens: repo_remaining,
                budget_exhausted: false,
            },
            repo_remaining,
        )
    };
    if !web_lines.is_empty() {
        if !lines.is_empty() {
            lines.push(String::new());
        }
        lines.push("Web context:".to_string());
        lines.extend(web_lines);
    }
    (
        lines.join("\n"),
        ChatContextTrace {
            profile: profile_trace,
            map: map_trace,
            memory: memory_trace,
            diff: diff_trace,
            repo: RepoContextTrace {
                candidates: repo_candidates,
                selected: repo_selected,
                budget_tokens: budgets.repo_tokens,
                budget_exhausted: repo_budget_exhausted,
            },
            symbols: symbol_trace,
            web: web_trace,
            repo_unused_tokens: repo_remaining,
        },
    )
}

fn build_reasoning_trace(
    profile_context: Option<&crate::orchestrator::ProfileContextAssembly>,
    memory_context: Option<&crate::orchestrator::MemoryContextAssembly>,
    hits: &[crate::index::Hit],
    web_context: Option<&[crate::orchestrator::web::WebFetchResult]>,
) -> Option<ReasoningTrace> {
    let mut style = Vec::new();
    let mut workflow = Vec::new();
    if let Some(context) = profile_context {
        for item in &context.items {
            match item.category {
                crate::profiles::PreferenceCategory::Style => {
                    style.push(truncate_compressed_text(&item.content));
                }
                crate::profiles::PreferenceCategory::Workflow => {
                    workflow.push(truncate_compressed_text(&item.content));
                }
                _ => {}
            }
        }
    }

    let mut memory = Vec::new();
    if let Some(context) = memory_context {
        for item in &context.items {
            memory.push(truncate_compressed_text(&item.content));
        }
    }

    let repo = hits
        .iter()
        .take(8)
        .map(|hit| hit.rel_path.clone())
        .collect::<Vec<_>>();

    let mut web = Vec::new();
    if let Some(context) = web_context {
        for item in context.iter().take(3) {
            web.push(item.url.clone());
        }
    }

    if style.is_empty()
        && workflow.is_empty()
        && memory.is_empty()
        && repo.is_empty()
        && web.is_empty()
    {
        None
    } else {
        Some(ReasoningTrace {
            behavioral_truth: BehavioralTruth { style, workflow },
            technical_truth: TechnicalTruth { memory, repo, web },
        })
    }
}

fn build_prompt(
    query: &str,
    context: &str,
    history: &str,
    history_budget: usize,
    budgets: &ChatContextBudgets,
) -> String {
    let (system, _) = truncate_to_tokens(CHAT_SYSTEM_PROMPT, budgets.system_tokens.max(1));
    let mut prompt = String::new();
    if !system.trim().is_empty() {
        prompt.push_str(system.trim());
        prompt.push_str("\n\n");
    }
    if context.trim().is_empty() {
        prompt.push_str("Context: <none>\n\n");
    } else {
        prompt.push_str("Context:\n");
        prompt.push_str(context.trim());
        prompt.push_str("\n\n");
    }
    if !history.trim().is_empty() && history_budget > 0 {
        let (history_snippet, _) = truncate_to_tokens(history.trim(), history_budget);
        if !history_snippet.trim().is_empty() {
            prompt.push_str("Conversation history:\n");
            prompt.push_str(history_snippet.trim());
            prompt.push_str("\n\n");
        }
    }
    prompt.push_str("User question:\n");
    prompt.push_str(query.trim());
    prompt.push_str("\n\nAnswer:");
    prompt
}

fn log_budget_drops(request_id: &str, repo_root: &Path, trace: &ChatContextTrace) {
    let profile_dropped = trace
        .profile
        .available
        .saturating_sub(trace.profile.selected);
    let profile_truncated = trace.profile.truncated;
    let map_dropped = trace.map.available.saturating_sub(trace.map.selected);
    let map_truncated = trace.map.truncated;
    let memory_dropped = trace.memory.available.saturating_sub(trace.memory.selected);
    let memory_truncated = trace.memory.truncated;
    let diff_dropped = if trace.diff.budget_exhausted {
        trace.diff.candidates.saturating_sub(trace.diff.selected)
    } else {
        0
    };
    let repo_dropped = if trace.repo.budget_exhausted {
        trace.repo.candidates.saturating_sub(trace.repo.selected)
    } else {
        0
    };
    let symbols_dropped = if trace.symbols.budget_exhausted {
        trace
            .symbols
            .candidates
            .saturating_sub(trace.symbols.selected)
    } else {
        0
    };
    let web_dropped = if trace.web.budget_exhausted {
        trace.web.candidates.saturating_sub(trace.web.selected)
    } else {
        0
    };
    let profile_drop_total = profile_dropped.saturating_add(profile_truncated);
    if profile_drop_total > 0 {
        crate::metrics::global().inc_profile_budget_drop(profile_drop_total);
    }

    if profile_dropped > 0
        || profile_truncated > 0
        || map_dropped > 0
        || map_truncated > 0
        || memory_dropped > 0
        || memory_truncated > 0
        || diff_dropped > 0
        || repo_dropped > 0
        || symbols_dropped > 0
        || web_dropped > 0
    {
        info!(
            target: "docdexd",
            request_id = %request_id,
            repo_root = %repo_root.display(),
            profile_dropped,
            profile_truncated,
            profile_budget_tokens = trace.profile.budget_tokens,
            map_dropped,
            map_truncated,
            map_budget_tokens = trace.map.budget_tokens,
            memory_dropped,
            memory_truncated,
            memory_budget_tokens = trace.memory.budget_tokens,
            diff_dropped,
            diff_budget_tokens = trace.diff.budget_tokens,
            repo_dropped,
            repo_budget_tokens = trace.repo.budget_tokens,
            symbols_dropped,
            symbols_budget_tokens = trace.symbols.budget_tokens,
            web_dropped,
            web_budget_tokens = trace.web.budget_tokens,
            "context pruned to fit token budget"
        );
    }
}

fn format_symbol_context_with_budget(
    symbols_context: &SymbolContextAssembly,
    budget_tokens: usize,
) -> (Vec<String>, SymbolContextTrace, usize) {
    let mut lines = Vec::new();
    let mut remaining = budget_tokens;
    let candidates = symbols_context.items.len();
    let mut selected = 0usize;
    let mut budget_exhausted = false;
    for item in &symbols_context.items {
        if remaining == 0 {
            budget_exhausted = true;
            break;
        }
        if item.symbols.is_empty() {
            continue;
        }
        let prefix = format!("- {}: ", item.file);
        let prefix_tokens = estimate_tokens(&prefix) as usize;
        if prefix_tokens >= remaining {
            budget_exhausted = true;
            break;
        }
        let available = remaining - prefix_tokens;
        let symbols_text = format_symbol_list(&item.symbols);
        let (trimmed_snippet, used_tokens) = truncate_to_tokens(&symbols_text, available);
        if trimmed_snippet.is_empty() {
            budget_exhausted = true;
            break;
        }
        lines.push(format!("{prefix}{trimmed_snippet}"));
        selected += 1;
        remaining = remaining.saturating_sub(prefix_tokens + used_tokens);
    }
    (
        lines,
        SymbolContextTrace {
            candidates,
            selected,
            budget_tokens,
            budget_exhausted,
        },
        remaining,
    )
}

fn format_symbol_list(symbols: &[crate::orchestrator::SymbolContextSymbol]) -> String {
    let mut out = Vec::with_capacity(symbols.len());
    for symbol in symbols {
        out.push(format_symbol_label(symbol));
    }
    out.join(", ")
}

fn format_symbol_label(symbol: &crate::orchestrator::SymbolContextSymbol) -> String {
    let signature = symbol
        .signature
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty());
    let mut label = if let Some(signature) = signature {
        signature.to_string()
    } else {
        format!("{} {}", symbol.kind, symbol.name)
    };
    if symbol.line_start > 0 {
        label.push_str(&format!("@L{}", symbol.line_start));
    }
    label
}
fn format_web_context_with_budget(
    web_context: &[crate::orchestrator::web::WebFetchResult],
    budget_tokens: usize,
) -> (Vec<String>, WebContextTrace, usize) {
    const MAX_CONTEXT_DOCS: usize = 3;
    const MAX_CONTEXT_CHARS: usize = 800;

    let mut lines = Vec::new();
    let mut remaining = budget_tokens;
    let candidates = web_context.iter().take(MAX_CONTEXT_DOCS).count();
    let mut selected = 0usize;
    let mut budget_exhausted = false;
    for item in web_context.iter().take(MAX_CONTEXT_DOCS) {
        if remaining == 0 {
            budget_exhausted = true;
            break;
        }
        let content = item.ai_digested_content.as_ref().or(item.content.as_ref());
        let Some(content) = content else {
            continue;
        };
        let trimmed = content.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (snippet, _) = crate::max_size::truncate_utf8_chars(trimmed, MAX_CONTEXT_CHARS);
        let prefix = format!("- {}: ", item.url);
        let prefix_tokens = estimate_tokens(&prefix) as usize;
        if prefix_tokens >= remaining {
            budget_exhausted = true;
            break;
        }
        let available = remaining - prefix_tokens;
        let (trimmed_snippet, used_tokens) = truncate_to_tokens(&snippet, available);
        if trimmed_snippet.is_empty() {
            budget_exhausted = true;
            break;
        }
        lines.push(format!("{prefix}{trimmed_snippet}"));
        selected += 1;
        remaining = remaining.saturating_sub(prefix_tokens + used_tokens);
    }
    (
        lines,
        WebContextTrace {
            candidates,
            selected,
            budget_tokens,
            budget_exhausted,
        },
        remaining,
    )
}

fn format_compressed_results(
    hits: &[crate::index::Hit],
    symbols_context: Option<&SymbolContextAssembly>,
    web_context: Option<&[crate::orchestrator::web::WebFetchResult]>,
    profile_context: Option<&crate::orchestrator::ProfileContextAssembly>,
    memory_context: Option<&crate::orchestrator::MemoryContextAssembly>,
    impact_context: Option<&crate::impact::ImpactContextAssembly>,
    budgets: &ChatContextBudgets,
) -> String {
    const MAX_COMPRESSED_PROFILE_ITEMS: usize = 3;
    const MAX_COMPRESSED_MEMORY_ITEMS: usize = 3;
    const MAX_COMPRESSED_DIFF_ITEMS: usize = 4;

    let local = build_compressed_local(hits, symbols_context);
    let web = best_web_summary(web_context);
    let (profile_snippets, _) =
        select_profile_snippets(profile_context, budgets.profile_tokens, None);
    let profile = if profile_snippets.is_empty() {
        None
    } else {
        Some(
            profile_snippets
                .into_iter()
                .take(MAX_COMPRESSED_PROFILE_ITEMS)
                .map(|snippet| CompressedProfileItem {
                    score: snippet.score,
                    category: snippet.category.to_string(),
                    content: truncate_compressed_text(snippet.content.trim()),
                })
                .collect(),
        )
    };
    let (memory_snippets, _) = select_memory_snippets(memory_context, budgets.memory_tokens);
    let memory = if memory_snippets.is_empty() {
        None
    } else {
        Some(
            memory_snippets
                .into_iter()
                .take(MAX_COMPRESSED_MEMORY_ITEMS)
                .map(|snippet| CompressedMemoryItem {
                    score: snippet.score,
                    content: truncate_compressed_text(snippet.content.trim()),
                })
                .collect(),
        )
    };
    let diff = impact_context.map(|context| CompressedDiffContext {
        sources: context
            .sources
            .iter()
            .take(MAX_COMPRESSED_DIFF_ITEMS)
            .cloned()
            .collect(),
        expanded: context
            .expanded_files
            .iter()
            .take(MAX_COMPRESSED_DIFF_ITEMS)
            .cloned()
            .collect(),
        truncated: context.sources.len() > MAX_COMPRESSED_DIFF_ITEMS
            || context.expanded_files.len() > MAX_COMPRESSED_DIFF_ITEMS,
    });
    let payload = CompressedEnvelope {
        results: CompressedResults {
            local,
            web,
            profile,
            memory,
            diff,
        },
    };
    serde_json::to_string(&payload).unwrap_or_else(|_| "{\"results\":{}}".to_string())
}

#[derive(Serialize)]
struct CompressedEnvelope {
    results: CompressedResults,
}

#[derive(Serialize)]
struct CompressedResults {
    #[serde(skip_serializing_if = "Option::is_none")]
    local: Option<CompressedLocal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    web: Option<CompressedWeb>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<Vec<CompressedProfileItem>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    memory: Option<Vec<CompressedMemoryItem>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diff: Option<CompressedDiffContext>,
}

#[derive(Serialize)]
struct CompressedLocal {
    score: f32,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,
}

#[derive(Serialize)]
struct CompressedWeb {
    score: f32,
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ai_digested_content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_snippet: Option<String>,
}

#[derive(Serialize)]
struct CompressedMemoryItem {
    score: f32,
    content: String,
}

#[derive(Serialize)]
struct CompressedProfileItem {
    score: f32,
    category: String,
    content: String,
}

#[derive(Serialize)]
struct CompressedDiffContext {
    sources: Vec<String>,
    expanded: Vec<String>,
    truncated: bool,
}

fn build_compressed_local(
    hits: &[crate::index::Hit],
    symbols_context: Option<&SymbolContextAssembly>,
) -> Option<CompressedLocal> {
    let hit = hits.first()?;
    let score = crate::search::normalize_score(hit.score);
    let mut summary = if !hit.summary.trim().is_empty() {
        Some(truncate_compressed_text(hit.summary.trim()))
    } else if !hit.snippet.trim().is_empty() {
        Some(truncate_compressed_text(hit.snippet.trim()))
    } else {
        None
    };
    if let Some(symbols_context) = symbols_context {
        if let Some(symbols_summary) =
            compressed_symbols_summary(symbols_context, hit.rel_path.as_str())
        {
            let combined = match summary.take() {
                Some(existing) => format!("{existing}\n{symbols_summary}"),
                None => symbols_summary,
            };
            summary = Some(truncate_compressed_text(combined.trim()));
        }
    }
    Some(CompressedLocal {
        score,
        path: hit.rel_path.clone(),
        summary,
    })
}

fn compressed_symbols_summary(
    symbols_context: &SymbolContextAssembly,
    rel_path: &str,
) -> Option<String> {
    const MAX_SYMBOLS: usize = 6;

    let item = symbols_context
        .items
        .iter()
        .find(|item| item.file == rel_path)?;
    if item.symbols.is_empty() {
        return None;
    }
    let mut labels = Vec::new();
    for symbol in item.symbols.iter().take(MAX_SYMBOLS) {
        labels.push(format_symbol_label(symbol));
    }
    if labels.is_empty() {
        return None;
    }
    Some(format!("Symbols: {}", labels.join(", ")))
}

fn best_web_summary(
    web_context: Option<&[crate::orchestrator::web::WebFetchResult]>,
) -> Option<CompressedWeb> {
    let items = web_context?;
    let mut best: Option<&crate::orchestrator::web::WebFetchResult> = None;
    for item in items {
        if item.relevance_score.is_none() && item.ai_digested_content.is_none() {
            continue;
        }
        match best {
            Some(current) => {
                if item.relevance_score.unwrap_or(0.0) > current.relevance_score.unwrap_or(0.0) {
                    best = Some(item);
                }
            }
            None => best = Some(item),
        }
    }
    let best = best?;
    let ai_digested_content = best.ai_digested_content.clone();
    let content_snippet = if ai_digested_content.is_none() {
        best.content
            .as_ref()
            .map(|content| truncate_compressed_text(content.trim()))
    } else {
        None
    };
    Some(CompressedWeb {
        score: best.relevance_score.unwrap_or(0.0),
        url: best.url.clone(),
        ai_digested_content,
        content_snippet,
    })
}

fn truncate_compressed_text(text: &str) -> String {
    const MAX_COMPRESS_CHARS: usize = 280;
    let (snippet, _) = crate::max_size::truncate_utf8_chars(text, MAX_COMPRESS_CHARS);
    snippet
}

fn truncate_to_tokens(text: &str, max_tokens: usize) -> (String, usize) {
    if max_tokens == 0 {
        return (String::new(), 0);
    }
    let mut out = String::new();
    let mut count = 0usize;
    let mut iter = text.split_whitespace();
    while count < max_tokens {
        let Some(token) = iter.next() else {
            break;
        };
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(token);
        count += 1;
    }
    let truncated = iter.next().is_some();
    if truncated && !out.is_empty() {
        out.push('…');
    }
    let used = estimate_tokens(&out) as usize;
    (out, used)
}

fn estimate_tokens(text: &str) -> u64 {
    text.split_whitespace()
        .filter(|token| !token.is_empty())
        .count() as u64
}

fn now_epoch_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn error_response(
    status: StatusCode,
    error_type: &'static str,
    code: &'static str,
    message: &str,
) -> Response {
    let body = OpenAiErrorResponse {
        error: OpenAiErrorDetail {
            message: message.to_string(),
            error_type,
            code: Some(code),
        },
    };
    (status, Json(body)).into_response()
}

fn stream_response<I>(chunks: I) -> Response
where
    I: IntoIterator<Item = ChatCompletionChunk>,
    I::IntoIter: Send + 'static,
{
    let frames = chunks
        .into_iter()
        .filter_map(|chunk| serde_json::to_string(&chunk).ok())
        .map(|json| Ok::<Bytes, Infallible>(Bytes::from(format!("data: {json}\n\n"))))
        .chain(std::iter::once(Ok(Bytes::from("data: [DONE]\n\n"))));
    let body = Body::from_stream(stream::iter(frames));
    let mut response = Response::new(body);
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    *response.status_mut() = StatusCode::OK;
    response
}

fn chunk_text(text: &str, max_chars: usize) -> Vec<String> {
    if max_chars == 0 {
        return vec![text.to_string()];
    }
    let mut chunks = Vec::new();
    let mut buf = String::new();
    let mut count = 0usize;
    for ch in text.chars() {
        buf.push(ch);
        count += 1;
        if count >= max_chars {
            chunks.push(buf);
            buf = String::new();
            count = 0;
        }
    }
    if !buf.is_empty() {
        chunks.push(buf);
    }
    chunks
}

fn queue_dag_log(
    repo_state_root: std::path::PathBuf,
    session_id: String,
    node_type: &'static str,
    payload: serde_json::Value,
) {
    tokio::spawn(async move {
        let session_id_log = session_id.clone();
        let result = tokio::task::spawn_blocking(move || {
            dag_logging::log_node(&repo_state_root, &session_id, node_type, &payload)
        })
        .await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => warn!(
                target: "docdexd",
                session_id = %session_id_log,
                error = ?err,
                "dag log failed"
            ),
            Err(err) => warn!(
                target: "docdexd",
                session_id = %session_id_log,
                error = ?err,
                "dag log task failed"
            ),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::impact::{ImpactContextAssembly, ImpactContextPruneTrace};
    use crate::index::{DocumentKind, Hit};
    use crate::memory::{MemoryContextItem, MemoryContextPruneTrace};
    use crate::orchestrator::MemoryContextAssembly;
    use crate::orchestrator::ProfileContextAssembly;
    use crate::profiles::{PreferenceCategory, ProfileContextItem, ProfileContextPruneTrace};
    use serde_json::json;

    #[test]
    fn diff_context_ordering_and_budgeting() {
        let hits = vec![Hit {
            doc_id: "doc-1".to_string(),
            rel_path: "docs/readme.md".to_string(),
            path: "docs/readme.md".to_string(),
            kind: DocumentKind::Doc,
            doc_type: None,
            score: 1.0,
            summary: "Repo summary text".to_string(),
            snippet: String::new(),
            token_estimate: 12,
            snippet_origin: None,
            snippet_truncated: None,
            line_start: None,
            line_end: None,
        }];

        let memory_context = MemoryContextAssembly {
            items: vec![MemoryContextItem {
                id: "mem-1".to_string(),
                created_at_ms: 0,
                score: 0.9,
                token_estimate: 3,
                truncated: false,
                content: "remember alpha".to_string(),
                metadata: json!({ "source": "test" }),
            }],
            prune_trace: MemoryContextPruneTrace {
                budget_tokens: 10,
                max_items: 5,
                candidates: 1,
                kept: 1,
                dropped: Vec::new(),
            },
        };

        let impact_context = ImpactContextAssembly {
            sources: vec!["src/a.rs".to_string(), "src/b.rs".to_string()],
            expanded_files: vec!["src/c.rs".to_string()],
            edges: Vec::new(),
            prune_trace: ImpactContextPruneTrace {
                requested_sources: 2,
                normalized_sources: 2,
                dropped_sources: 0,
                expanded_files: 1,
                max_edges: 10,
                max_depth: 1,
                edges: 1,
                truncated: false,
            },
        };

        let budgets = ChatContextBudgets {
            system_tokens: 0,
            profile_tokens: 0,
            map_tokens: 0,
            memory_tokens: 10,
            diff_tokens: 5,
            repo_tokens: 20,
            history_tokens: 0,
        };

        let (context, trace) = build_context_summary(
            "hello",
            &hits,
            None,
            None,
            None,
            None,
            false,
            Some(&memory_context),
            Some(&impact_context),
            &budgets,
        );

        let memory_pos = context.find("Memory context:").expect("memory context");
        let diff_pos = context.find("Diff context:").expect("diff context");
        let repo_pos = context.find("Top local matches").expect("repo context");
        assert!(memory_pos < diff_pos);
        assert!(diff_pos < repo_pos);
        assert!(trace.diff.budget_exhausted);
        assert_eq!(trace.diff.selected, 1);
    }

    #[test]
    fn profile_context_ordering_and_budgeting() {
        let hits = vec![Hit {
            doc_id: "doc-1".to_string(),
            rel_path: "docs/readme.md".to_string(),
            path: "docs/readme.md".to_string(),
            kind: DocumentKind::Doc,
            doc_type: None,
            score: 1.0,
            summary: "Repo summary text".to_string(),
            snippet: String::new(),
            token_estimate: 12,
            snippet_origin: None,
            snippet_truncated: None,
            line_start: None,
            line_end: None,
        }];

        let profile_context = ProfileContextAssembly {
            items: vec![
                ProfileContextItem {
                    id: "pref-1".to_string(),
                    agent_id: "agent-1".to_string(),
                    category: PreferenceCategory::Style,
                    last_updated: 0,
                    score: 0.9,
                    token_estimate: 3,
                    truncated: false,
                    content: "Keep responses concise".to_string(),
                },
                ProfileContextItem {
                    id: "pref-2".to_string(),
                    agent_id: "agent-1".to_string(),
                    category: PreferenceCategory::Tooling,
                    last_updated: 0,
                    score: 0.8,
                    token_estimate: 3,
                    truncated: false,
                    content: "Prefer ripgrep for search".to_string(),
                },
            ],
            prune_trace: ProfileContextPruneTrace {
                budget_tokens: 6,
                max_items: 5,
                candidates: 2,
                kept: 2,
                dropped: Vec::new(),
            },
        };

        let memory_context = MemoryContextAssembly {
            items: vec![MemoryContextItem {
                id: "mem-1".to_string(),
                created_at_ms: 0,
                score: 0.9,
                token_estimate: 3,
                truncated: false,
                content: "remember alpha".to_string(),
                metadata: json!({ "source": "test" }),
            }],
            prune_trace: MemoryContextPruneTrace {
                budget_tokens: 10,
                max_items: 5,
                candidates: 1,
                kept: 1,
                dropped: Vec::new(),
            },
        };

        let budgets = ChatContextBudgets {
            system_tokens: 0,
            profile_tokens: 3,
            map_tokens: 0,
            memory_tokens: 10,
            diff_tokens: 0,
            repo_tokens: 20,
            history_tokens: 0,
        };

        let (context, trace) = build_context_summary(
            "hello",
            &hits,
            None,
            None,
            Some(&profile_context),
            None,
            false,
            Some(&memory_context),
            None,
            &budgets,
        );

        let profile_pos = context
            .find("Style preferences (advisory):")
            .expect("profile context");
        let memory_pos = context.find("Memory context:").expect("memory context");
        let repo_pos = context.find("Top local matches").expect("repo context");
        assert!(profile_pos < memory_pos);
        assert!(memory_pos < repo_pos);
        assert_eq!(trace.profile.available, 1);
        assert_eq!(trace.profile.selected, 1);
    }

    #[test]
    fn history_budget_reuses_repo_unused_tokens() {
        let budgets = ChatContextBudgets {
            system_tokens: 0,
            profile_tokens: 0,
            map_tokens: 0,
            memory_tokens: 0,
            diff_tokens: 0,
            repo_tokens: 20,
            history_tokens: 0,
        };

        let (context, trace) = build_context_summary(
            "hello",
            &[],
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            &budgets,
        );

        assert!(trace.repo_unused_tokens > 0);
        let history = "user: one two three four five six seven eight nine ten";
        let history_budget = budgets
            .history_tokens
            .saturating_add(trace.repo_unused_tokens);
        let prompt = build_prompt("hello", &context, history, history_budget, &budgets);

        assert!(prompt.contains("Conversation history:"));
        assert!(prompt.contains("one"));
    }
}
