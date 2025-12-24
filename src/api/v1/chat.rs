use axum::extract::Query;
use axum::{extract::State, http::header::CONTENT_TYPE, http::HeaderMap, http::HeaderValue};
use axum::{http::StatusCode, Json};
use axum::{response::IntoResponse, response::Response};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::orchestrator::{run_waterfall, MemoryBudget, WaterfallRequest, WebGateConfig};
use crate::search::AppState;
use crate::tier2::Tier2Config;

const DEFAULT_LIMIT: usize = 8;

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
        true,
    ) {
        return error_response(err.status, err.code, &err.message);
    }
    let query = match extract_user_query(&payload.messages) {
        Some(value) => value,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "missing_query",
                "messages must include a user message",
            );
        }
    };
    if query.trim().is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_query",
            "user message content must not be empty",
        );
    }
    if state.security.max_query_bytes > 0 && query.len() > state.security.max_query_bytes {
        return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
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

    let web_gate = WebGateConfig::from_env();
    let request_id = Uuid::new_v4().to_string();
    let response = match run_waterfall(WaterfallRequest {
        request_id: &request_id,
        query: &query,
        limit,
        force_web,
        indexer: state.indexer.as_ref(),
        libs_indexer,
        web_gate: &web_gate,
        tier2_config: Tier2Config::enabled(),
        tier2_limiter: None,
        memory: state.memory.as_ref(),
        memory_budget: MemoryBudget::default(),
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
                let chunk = ChatCompletionChunk {
                    id: id.clone(),
                    object: "chat.completion.chunk",
                    created,
                    model: model.clone(),
                    choices: vec![ChatChunkChoice {
                        index: 0,
                        delta: ChatChunkDelta {
                            role: Some("assistant"),
                            content: Some(content.clone()),
                        },
                        finish_reason: None,
                    }],
                };
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
                return stream_response(&[chunk, final_chunk]);
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
                "internal_error",
                &err.to_string(),
            );
        }
    };

    (StatusCode::OK, Json(response)).into_response()
}

fn extract_user_query(messages: &[ChatMessage]) -> Option<String> {
    messages.iter().rev().find_map(|message| {
        if message.role.to_ascii_lowercase() != "user" {
            return None;
        }
        match &message.content {
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
    })
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

fn error_response(status: StatusCode, code: &'static str, message: &str) -> Response {
    let body = OpenAiErrorResponse {
        error: OpenAiErrorDetail {
            message: message.to_string(),
            error_type: "invalid_request_error",
            code: Some(code),
        },
    };
    (status, Json(body)).into_response()
}

fn stream_response(chunks: &[ChatCompletionChunk]) -> Response {
    let mut body = String::new();
    for chunk in chunks {
        if let Ok(json) = serde_json::to_string(chunk) {
            body.push_str("data: ");
            body.push_str(&json);
            body.push_str("\n\n");
        }
    }
    body.push_str("data: [DONE]\n\n");

    let mut response = Response::new(body.into());
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    *response.status_mut() = StatusCode::OK;
    response
}
