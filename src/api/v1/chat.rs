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
use std::convert::Infallible;
use uuid::Uuid;

use crate::orchestrator::{
    run_waterfall, MemoryBudget, WaterfallPlan, WaterfallRequest, WebGateConfig,
};
use crate::search::AppState;
use crate::tier2::Tier2Config;

const DEFAULT_LIMIT: usize = 8;
const STREAM_CHUNK_CHARS: usize = 320;

#[derive(Debug, Deserialize)]
struct ChatCompletionRequest {
    model: Option<String>,
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
    include_libs: Option<bool>,
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
struct RepoIdQuery {
    #[serde(default)]
    repo_id: Option<String>,
}

pub async fn chat_completions_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(repo_id): Query<RepoIdQuery>,
    Json(payload): Json<ChatCompletionRequest>,
) -> Response {
    if let Err(err) = crate::search::resolve_repo_id(
        &headers,
        repo_id.repo_id.as_deref(),
        payload.repo_id.as_deref(),
        state.indexer.as_ref(),
        false,
    ) {
        return error_response(err.status, "invalid_request_error", err.code, &err.message);
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
    let limit = docdex
        .and_then(|opts| opts.limit)
        .unwrap_or(DEFAULT_LIMIT)
        .min(state.security.max_limit);
    let force_web = docdex.and_then(|opts| opts.force_web).unwrap_or(false);
    let include_libs = docdex.and_then(|opts| opts.include_libs).unwrap_or(true);
    let libs_indexer = if include_libs {
        state.libs_indexer.as_deref()
    } else {
        None
    };

    let plan = WaterfallPlan::new(
        WebGateConfig::from_env(),
        Tier2Config::enabled(),
        MemoryBudget::default(),
    );
    let request_id = Uuid::new_v4().to_string();
    let query_with_context = if extracted.context.trim().is_empty() {
        query.clone()
    } else {
        format!("{}\n\nUser:\n{}", extracted.context, query)
    };
    let response = match run_waterfall(WaterfallRequest {
        request_id: &request_id,
        query: &query_with_context,
        limit,
        force_web,
        indexer: state.indexer.as_ref(),
        libs_indexer,
        plan,
        tier2_limiter: None,
        memory: state.memory.as_ref(),
    })
    .await
    {
        Ok(result) => {
            let content = build_completion(&query, &result.search_response.hits);
            let prompt_tokens = estimate_tokens(&query);
            let completion_tokens = estimate_tokens(&content);
            let usage = Usage {
                prompt_tokens,
                completion_tokens,
                total_tokens: prompt_tokens + completion_tokens,
            };
            let model = payload
                .model
                .clone()
                .unwrap_or_else(|| "docdex".to_string());
            let created = now_epoch_seconds();
            if payload.stream {
                let id = format!("chatcmpl-{}", request_id);
                let mut content_chunks = chunk_text(&content, STREAM_CHUNK_CHARS);
                if content_chunks.is_empty() {
                    content_chunks.push(String::new());
                }
                let content_iter = content_chunks.into_iter().enumerate().map(|(idx, piece)| {
                    let role = if idx == 0 { Some("assistant") } else { None };
                    ChatCompletionChunk {
                        id: id.clone(),
                        object: "chat.completion.chunk",
                        created,
                        model: model.clone(),
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
                    id: id.clone(),
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
}

fn extract_query_and_context(messages: &[ChatMessage]) -> Option<ChatQueryContext> {
    let mut context_parts: Vec<String> = Vec::new();
    let mut last_user: Option<String> = None;

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
        if role == "user" {
            last_user = Some(trimmed.to_string());
        }
    }

    let query = last_user?;
    let context = context_parts.join("\n\n");
    Some(ChatQueryContext { query, context })
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

fn build_completion(query: &str, hits: &[crate::index::Hit]) -> String {
    if hits.is_empty() {
        return format!("No local documents matched query: {}", query.trim());
    }

    let mut lines = Vec::new();
    let trimmed = query.trim();
    if trimmed.is_empty() {
        lines.push("Top local matches:".to_string());
    } else {
        lines.push(format!("Top local matches for query: {}", trimmed));
    }
    for hit in hits.iter().take(5) {
        let summary = hit.summary.trim();
        if summary.is_empty() {
            lines.push(format!("- {}", hit.rel_path));
        } else {
            lines.push(format!("- {}: {}", hit.rel_path, summary));
        }
    }
    lines.join("\n")
}

fn estimate_tokens(text: &str) -> u64 {
    text.split_whitespace().filter(|token| !token.is_empty()).count() as u64
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
{
    let frames = chunks
        .into_iter()
        .filter_map(|chunk| serde_json::to_string(&chunk).ok())
        .map(|json| Ok(Bytes::from(format!("data: {json}\n\n"))))
        .chain(std::iter::once(Ok(Bytes::from("data: [DONE]\n\n"))));
    let body = Body::from_stream(stream::iter(frames));
    let mut response = Response::new(body);
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
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
