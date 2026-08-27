use crate::conversations::types::{ConversationImport, ConversationMessage, ConversationRole};
use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversationImportFormat {
    Auto,
    PlainText,
    GenericJson,
    CodexJsonl,
    ClaudeJsonl,
    ChatgptExport,
}

impl ConversationImportFormat {
    pub fn parse(value: Option<&str>) -> Result<Self, String> {
        match value
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("auto")
            .to_ascii_lowercase()
            .as_str()
        {
            "auto" => Ok(Self::Auto),
            "plain_text" | "plain-text" | "plain" | "text" => Ok(Self::PlainText),
            "generic_json" | "generic-json" | "json" => Ok(Self::GenericJson),
            "codex_jsonl" | "codex-jsonl" => Ok(Self::CodexJsonl),
            "claude_jsonl" | "claude-jsonl" => Ok(Self::ClaudeJsonl),
            "chatgpt_export" | "chatgpt-export" => Ok(Self::ChatgptExport),
            other => Err(format!("unsupported conversation import format: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::PlainText => "plain_text",
            Self::GenericJson => "generic_json",
            Self::CodexJsonl => "codex_jsonl",
            Self::ClaudeJsonl => "claude_jsonl",
            Self::ChatgptExport => "chatgpt_export",
        }
    }

    fn default_source(&self) -> &'static str {
        match self {
            Self::CodexJsonl => "codex",
            Self::ClaudeJsonl => "claude",
            Self::ChatgptExport => "chatgpt",
            _ => "manual",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConversationImportEnvelope {
    pub source: Option<String>,
    pub source_session_id: Option<String>,
    pub title: Option<String>,
    pub agent_id: Option<String>,
    pub transport: Option<String>,
    pub started_at_ms: Option<i64>,
    pub ended_at_ms: Option<i64>,
    pub format: Option<String>,
    pub messages: Option<Vec<ConversationMessage>>,
    pub transcript_text: Option<String>,
    pub metadata: Value,
}

#[derive(Debug, Default)]
struct ParsedConversation {
    source: Option<String>,
    source_session_id: Option<String>,
    title: Option<String>,
    transport: Option<String>,
    started_at_ms: Option<i64>,
    ended_at_ms: Option<i64>,
    messages: Vec<ConversationMessage>,
    metadata: Value,
}

#[derive(Debug)]
struct SearchTextCandidate {
    role: ConversationRole,
    content: String,
    author: Option<String>,
    created_at_ms: Option<i64>,
    metadata: Value,
}

pub fn normalize_import_request(
    input: ConversationImportEnvelope,
) -> Result<ConversationImport, String> {
    let ConversationImportEnvelope {
        source,
        source_session_id,
        title,
        agent_id,
        transport,
        started_at_ms,
        ended_at_ms,
        format,
        messages,
        transcript_text,
        metadata,
    } = input;
    let format = ConversationImportFormat::parse(format.as_deref())?;
    let parsed = match messages {
        Some(messages) => ParsedConversation {
            messages: normalize_supplied_messages(messages)?,
            metadata: json!({}),
            ..ParsedConversation::default()
        },
        None => parse_transcript_input(format, transcript_text.as_deref())?,
    };
    if parsed.messages.is_empty() {
        return Err("conversation import did not produce any messages".to_string());
    }
    let resolved_source = source
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or(parsed.source)
        .unwrap_or_else(|| format.default_source().to_string());
    let started_at_ms = started_at_ms
        .or(parsed.started_at_ms)
        .or_else(|| parsed.messages.first().and_then(|item| item.created_at_ms));
    let ended_at_ms = ended_at_ms
        .or(parsed.ended_at_ms)
        .or_else(|| parsed.messages.last().and_then(|item| item.created_at_ms));
    Ok(ConversationImport {
        source: resolved_source,
        source_session_id: normalize_optional_text(source_session_id).or(parsed.source_session_id),
        title: normalize_optional_text(title).or(parsed.title),
        agent_id: normalize_optional_text(agent_id),
        transport: normalize_optional_text(transport).or(parsed.transport),
        started_at_ms,
        ended_at_ms,
        messages: parsed.messages,
        metadata: merge_metadata(parsed.metadata, metadata, format.as_str()),
    })
}

pub fn normalize_supplied_messages(
    messages: Vec<ConversationMessage>,
) -> Result<Vec<ConversationMessage>, String> {
    let normalized = messages
        .into_iter()
        .filter_map(normalize_message)
        .collect::<Vec<_>>();
    if normalized.is_empty() {
        return Err("messages must contain at least one non-empty item".to_string());
    }
    Ok(normalized)
}

fn parse_transcript_input(
    format: ConversationImportFormat,
    transcript_text: Option<&str>,
) -> Result<ParsedConversation, String> {
    let input = transcript_text
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "either messages or transcript_text is required".to_string())?;
    let parsed = match format {
        ConversationImportFormat::Auto => parse_auto_transcript(input),
        ConversationImportFormat::PlainText => parse_plain_text_transcript(input),
        ConversationImportFormat::GenericJson => parse_generic_json_transcript(input),
        ConversationImportFormat::CodexJsonl => parse_codex_jsonl(input),
        ConversationImportFormat::ClaudeJsonl => parse_generic_jsonl(input, "claude"),
        ConversationImportFormat::ChatgptExport => parse_chatgpt_export(input),
    }?;
    if parsed.messages.is_empty() {
        return Err("transcript_text must contain at least one message".to_string());
    }
    Ok(parsed)
}

fn parse_auto_transcript(input: &str) -> Result<ParsedConversation, String> {
    if looks_like_jsonl(input) {
        if let Ok(parsed) = parse_codex_jsonl(input) {
            if !parsed.messages.is_empty() {
                return Ok(parsed);
            }
        }
        if let Ok(parsed) = parse_generic_jsonl(input, "manual") {
            if !parsed.messages.is_empty() {
                return Ok(parsed);
            }
        }
    }
    let trimmed = input.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if let Ok(parsed) = parse_chatgpt_export(input) {
            if !parsed.messages.is_empty() {
                return Ok(parsed);
            }
        }
        if let Ok(parsed) = parse_generic_json_transcript(input) {
            if !parsed.messages.is_empty() {
                return Ok(parsed);
            }
        }
    }
    parse_plain_text_transcript(input)
}

fn parse_plain_text_transcript(input: &str) -> Result<ParsedConversation, String> {
    let mut messages = Vec::new();
    let mut current_role: Option<ConversationRole> = None;
    let mut current_content = String::new();
    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((role, content)) = parse_prefixed_role_line(trimmed) {
            push_plain_text_message(&mut messages, current_role.take(), &current_content);
            current_content.clear();
            current_role = Some(role);
            current_content.push_str(content);
            continue;
        }
        if !current_content.is_empty() {
            current_content.push('\n');
        }
        current_content.push_str(trimmed);
        if current_role.is_none() {
            current_role = Some(ConversationRole::User);
        }
    }
    push_plain_text_message(&mut messages, current_role.take(), &current_content);
    Ok(ParsedConversation {
        messages: normalize_supplied_messages(messages)?,
        metadata: json!({}),
        ..ParsedConversation::default()
    })
}

fn push_plain_text_message(
    messages: &mut Vec<ConversationMessage>,
    role: Option<ConversationRole>,
    content: &str,
) {
    let Some(role) = role else {
        return;
    };
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return;
    }
    messages.push(ConversationMessage {
        role,
        content: trimmed.to_string(),
        author: None,
        created_at_ms: None,
        metadata: json!({}),
    });
}

fn parse_generic_json_transcript(input: &str) -> Result<ParsedConversation, String> {
    let value: Value = serde_json::from_str(input)
        .map_err(|err| format!("invalid generic_json payload: {err}"))?;
    parse_generic_json_value(&value)
}

fn parse_generic_json_value(value: &Value) -> Result<ParsedConversation, String> {
    if looks_like_chatgpt_export(value) {
        return parse_chatgpt_export_value(value);
    }
    if let Some(messages_value) = value.get("messages") {
        let messages = collect_messages_from_value(messages_value)?;
        return Ok(ParsedConversation {
            source_session_id: first_string(
                value,
                &[&["source_session_id"], &["session_id"], &["id"]],
            ),
            title: first_string(value, &[&["title"], &["name"]]),
            started_at_ms: parse_timestamp_value(first_value(
                value,
                &[&["started_at_ms"], &["started_at"], &["created_at"]],
            )),
            ended_at_ms: parse_timestamp_value(first_value(
                value,
                &[&["ended_at_ms"], &["ended_at"], &["updated_at"]],
            )),
            messages,
            metadata: object_or_empty(value.clone()),
            ..ParsedConversation::default()
        });
    }
    if let Some(message) = value_to_message(value, None) {
        return Ok(ParsedConversation {
            messages: normalize_supplied_messages(vec![message])?,
            metadata: object_or_empty(value.clone()),
            ..ParsedConversation::default()
        });
    }
    if let Some(array) = value.as_array() {
        let messages = collect_messages_from_value(&Value::Array(array.clone()))?;
        return Ok(ParsedConversation {
            messages,
            metadata: json!({}),
            ..ParsedConversation::default()
        });
    }
    Err("generic_json did not contain any message records".to_string())
}

fn parse_codex_jsonl(input: &str) -> Result<ParsedConversation, String> {
    let mut parsed = ParsedConversation {
        source: Some("codex".to_string()),
        metadata: json!({}),
        ..ParsedConversation::default()
    };
    let mut saw_line = false;
    for (idx, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        saw_line = true;
        let value: Value = serde_json::from_str(line)
            .map_err(|err| format!("invalid codex_jsonl line {}: {err}", idx + 1))?;
        let line_ts = parse_timestamp_value(value.get("timestamp").or_else(|| value.get("ts")));
        match value.get("type").and_then(Value::as_str) {
            Some("session_meta") => {
                parsed.source_session_id = parsed
                    .source_session_id
                    .or_else(|| first_string(&value, &[&["payload", "id"], &["id"]]));
                parsed.title = parsed
                    .title
                    .or_else(|| first_string(&value, &[&["payload", "title"], &["title"]]));
                parsed.started_at_ms = parsed.started_at_ms.or(line_ts);
                parsed.metadata = merge_metadata(
                    parsed.metadata,
                    value
                        .get("payload")
                        .cloned()
                        .map(object_or_empty)
                        .unwrap_or_else(|| json!({})),
                    "codex_jsonl",
                );
            }
            Some("event_msg") => {
                if let Some(payload) = value.get("payload") {
                    if let Some(message) = codex_event_message(payload, line_ts) {
                        parsed.messages.push(message);
                    }
                }
            }
            Some("response_item") => {
                if let Some(payload) = value.get("payload") {
                    if payload.get("type").and_then(Value::as_str) == Some("message") {
                        if let Some(message) = value_to_message(payload, line_ts) {
                            parsed.messages.push(message);
                        }
                    }
                }
            }
            _ => {
                if let Some(payload) = value.get("payload") {
                    if let Some(message) = value_to_message(payload, line_ts) {
                        parsed.messages.push(message);
                    }
                } else if let Some(message) = value_to_message(&value, line_ts) {
                    parsed.messages.push(message);
                }
            }
        }
        parsed.ended_at_ms = line_ts.or(parsed.ended_at_ms);
    }
    if !saw_line {
        return Err("codex_jsonl transcript is empty".to_string());
    }
    parsed.messages = normalize_supplied_messages(parsed.messages)?;
    Ok(parsed)
}

fn codex_event_message(payload: &Value, created_at_ms: Option<i64>) -> Option<ConversationMessage> {
    let role = match payload.get("type").and_then(Value::as_str)? {
        "user_message" => ConversationRole::User,
        "assistant_message" => ConversationRole::Assistant,
        "system_message" => ConversationRole::System,
        "developer_message" => ConversationRole::Developer,
        _ => return value_to_message(payload, created_at_ms),
    };
    let content = extract_text(
        payload
            .get("message")
            .or_else(|| payload.get("text"))
            .or_else(|| payload.get("content"))?,
    )?;
    Some(ConversationMessage {
        role,
        content,
        author: first_string(payload, &[&["author"], &["kind"]]),
        created_at_ms,
        metadata: object_or_empty(payload.clone()),
    })
}

fn parse_generic_jsonl(input: &str, source: &str) -> Result<ParsedConversation, String> {
    let mut parsed = ParsedConversation {
        source: Some(source.to_string()),
        metadata: json!({}),
        ..ParsedConversation::default()
    };
    let mut saw_line = false;
    for (idx, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        saw_line = true;
        let value: Value = serde_json::from_str(line)
            .map_err(|err| format!("invalid {} line {}: {err}", source, idx + 1))?;
        let line_ts = parse_timestamp_value(value.get("timestamp").or_else(|| value.get("ts")));
        if parsed.source_session_id.is_none() {
            parsed.source_session_id =
                first_string(&value, &[&["session_id"], &["conversation_id"], &["id"]]);
        }
        if parsed.title.is_none() {
            parsed.title = first_string(&value, &[&["title"], &["name"]]);
        }
        if let Some(message) = value_to_message(&value, line_ts)
            .or_else(|| {
                value
                    .get("payload")
                    .and_then(|value| value_to_message(value, line_ts))
            })
            .or_else(|| {
                value
                    .get("message")
                    .and_then(|value| value_to_message(value, line_ts))
            })
        {
            parsed.messages.push(message);
        }
        parsed.started_at_ms = parsed.started_at_ms.or(line_ts);
        parsed.ended_at_ms = line_ts.or(parsed.ended_at_ms);
    }
    if !saw_line {
        return Err(format!("{source} transcript is empty"));
    }
    parsed.messages = normalize_supplied_messages(parsed.messages)?;
    Ok(parsed)
}

fn parse_chatgpt_export(input: &str) -> Result<ParsedConversation, String> {
    let value: Value = serde_json::from_str(input)
        .map_err(|err| format!("invalid chatgpt_export payload: {err}"))?;
    parse_chatgpt_export_value(&value)
}

fn parse_chatgpt_export_value(value: &Value) -> Result<ParsedConversation, String> {
    let root = if let Some(array) = value.as_array() {
        if array.len() != 1 {
            return Err("chatgpt_export must contain exactly one conversation".to_string());
        }
        &array[0]
    } else {
        value
    };
    let mapping = root
        .get("mapping")
        .and_then(Value::as_object)
        .ok_or_else(|| "chatgpt_export is missing mapping".to_string())?;
    let mut candidates = Vec::new();
    for node in mapping.values() {
        let Some(message) = node.get("message") else {
            continue;
        };
        let role = first_string(message, &[&["author", "role"], &["role"]])
            .map(|value| ConversationRole::from_str(&value))
            .unwrap_or(ConversationRole::Other);
        let content = extract_text(
            message
                .get("content")
                .or_else(|| message.get("text"))
                .unwrap_or(&Value::Null),
        );
        let Some(content) = content else {
            continue;
        };
        let created_at_ms = parse_timestamp_value(
            message
                .get("create_time")
                .or_else(|| node.get("create_time"))
                .or_else(|| message.get("created_at")),
        );
        candidates.push(SearchTextCandidate {
            role,
            content,
            author: first_string(message, &[&["author", "name"]]),
            created_at_ms,
            metadata: object_or_empty(message.clone()),
        });
    }
    candidates.sort_by(|a, b| {
        a.created_at_ms
            .unwrap_or_default()
            .cmp(&b.created_at_ms.unwrap_or_default())
    });
    let messages = candidates
        .into_iter()
        .map(|candidate| ConversationMessage {
            role: candidate.role,
            content: candidate.content,
            author: candidate.author,
            created_at_ms: candidate.created_at_ms,
            metadata: candidate.metadata,
        })
        .collect::<Vec<_>>();
    Ok(ParsedConversation {
        source: Some("chatgpt".to_string()),
        source_session_id: first_string(root, &[&["id"], &["conversation_id"]]),
        title: first_string(root, &[&["title"]]),
        started_at_ms: messages.first().and_then(|item| item.created_at_ms),
        ended_at_ms: messages.last().and_then(|item| item.created_at_ms),
        messages: normalize_supplied_messages(messages)?,
        metadata: object_or_empty(root.clone()),
        ..ParsedConversation::default()
    })
}

fn collect_messages_from_value(value: &Value) -> Result<Vec<ConversationMessage>, String> {
    let mut messages = Vec::new();
    match value {
        Value::Array(items) => {
            for item in items {
                if let Some(message) = value_to_message(item, None) {
                    messages.push(message);
                }
            }
        }
        other => {
            if let Some(message) = value_to_message(other, None) {
                messages.push(message);
            }
        }
    }
    normalize_supplied_messages(messages)
}

fn value_to_message(value: &Value, created_at_ms: Option<i64>) -> Option<ConversationMessage> {
    let role = first_string(
        value,
        &[
            &["role"],
            &["author", "role"],
            &["message", "author", "role"],
            &["payload", "role"],
            &["payload", "author", "role"],
        ],
    )
    .or_else(|| {
        match first_string(
            value,
            &[&["type"], &["payload", "type"], &["message", "type"]],
        )?
        .to_ascii_lowercase()
        .as_str()
        {
            "user_message" | "user" => Some("user".to_string()),
            "assistant_message" | "assistant" | "message" => Some("assistant".to_string()),
            "system_message" | "system" => Some("system".to_string()),
            "developer_message" | "developer" => Some("developer".to_string()),
            "tool" | "tool_message" => Some("tool".to_string()),
            _ => None,
        }
    })?;
    let content = extract_text(first_value(
        value,
        &[
            &["content"],
            &["text"],
            &["message", "content"],
            &["message", "text"],
            &["payload", "content"],
            &["payload", "text"],
            &["payload", "message"],
            &["message"],
        ],
    )?)?;
    normalize_message(ConversationMessage {
        role: ConversationRole::from_str(&role),
        content,
        author: first_string(
            value,
            &[
                &["author"],
                &["author", "name"],
                &["message", "author", "name"],
                &["payload", "author"],
                &["payload", "author", "name"],
            ],
        ),
        created_at_ms: created_at_ms.or_else(|| {
            parse_timestamp_value(first_value(
                value,
                &[
                    &["created_at_ms"],
                    &["timestamp_ms"],
                    &["created_at"],
                    &["timestamp"],
                    &["ts"],
                    &["message", "created_at"],
                    &["payload", "created_at"],
                ],
            ))
        }),
        metadata: object_or_empty(value.clone()),
    })
}

fn parse_prefixed_role_line(input: &str) -> Option<(ConversationRole, &str)> {
    for prefix in ["system", "user", "assistant", "tool", "developer"] {
        let needle = format!("{prefix}:");
        if input
            .get(..needle.len())
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(&needle))
        {
            return Some((
                ConversationRole::from_str(prefix),
                input[needle.len()..].trim_start(),
            ));
        }
    }
    None
}

fn normalize_message(mut message: ConversationMessage) -> Option<ConversationMessage> {
    let content = message.content.trim();
    if content.is_empty() {
        return None;
    }
    message.content = content.to_string();
    message.author = normalize_optional_text(message.author);
    message.metadata = object_or_empty(message.metadata);
    Some(message)
}

fn normalize_optional_text(value: Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn merge_metadata(parsed: Value, explicit: Value, format: &str) -> Value {
    let mut merged = Map::new();
    if let Value::Object(parsed_obj) = object_or_empty(parsed) {
        for (key, value) in parsed_obj {
            merged.insert(key, value);
        }
    }
    if let Value::Object(explicit_obj) = object_or_empty(explicit) {
        for (key, value) in explicit_obj {
            merged.insert(key, value);
        }
    }
    merged
        .entry("import_format".to_string())
        .or_insert_with(|| Value::String(format.to_string()));
    Value::Object(merged)
}

fn object_or_empty(value: Value) -> Value {
    match value {
        Value::Object(_) => value,
        _ => json!({}),
    }
}

fn looks_like_jsonl(input: &str) -> bool {
    let mut non_empty = input.lines().map(str::trim).filter(|line| !line.is_empty());
    let Some(first) = non_empty.next() else {
        return false;
    };
    first.starts_with('{') && non_empty.next().is_some()
}

fn looks_like_chatgpt_export(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.contains_key("mapping"),
        Value::Array(items) => items.len() == 1 && items[0].get("mapping").is_some(),
        _ => false,
    }
}

fn extract_text(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        Value::Array(items) => {
            let joined = items
                .iter()
                .filter_map(extract_text)
                .filter(|text| !text.is_empty())
                .collect::<Vec<_>>()
                .join("\n");
            if joined.trim().is_empty() {
                None
            } else {
                Some(joined)
            }
        }
        Value::Object(map) => {
            for key in ["text", "content", "parts", "message", "value"] {
                if let Some(text) = map.get(key).and_then(extract_text) {
                    return Some(text);
                }
            }
            None
        }
        other => {
            let text = other.to_string();
            let trimmed = text.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
    }
}

fn parse_timestamp_value(value: Option<&Value>) -> Option<i64> {
    let value = value?;
    match value {
        Value::Number(number) => number.as_i64().map(normalize_epoch_ms),
        Value::String(text) => parse_timestamp_str(text),
        _ => None,
    }
}

fn parse_timestamp_str(value: &str) -> Option<i64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(number) = trimmed.parse::<i64>() {
        return Some(normalize_epoch_ms(number));
    }
    DateTime::parse_from_rfc3339(trimmed)
        .ok()
        .map(|value| value.with_timezone(&Utc).timestamp_millis())
}

fn normalize_epoch_ms(value: i64) -> i64 {
    if value.abs() >= 100_000_000_000 {
        value
    } else {
        value.saturating_mul(1000)
    }
}

fn first_value<'a>(value: &'a Value, paths: &[&[&str]]) -> Option<&'a Value> {
    for path in paths {
        let mut current = value;
        let mut found = true;
        for segment in *path {
            let Some(next) = current.get(*segment) else {
                found = false;
                break;
            };
            current = next;
        }
        if found {
            return Some(current);
        }
    }
    None
}

fn first_string(value: &Value, paths: &[&[&str]]) -> Option<String> {
    first_value(value, paths).and_then(extract_text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_codex_jsonl_transcript() {
        let input = r#"{"timestamp":"2026-04-07T10:00:00Z","type":"session_meta","payload":{"id":"codex-session-1","source":"vscode"}}
{"timestamp":"2026-04-07T10:00:01Z","type":"event_msg","payload":{"type":"user_message","message":"Add archive search.","kind":"plain"}}
{"timestamp":"2026-04-07T10:00:02Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Next step: add /v1/conversations/search."}]}}"#;
        let parsed = parse_codex_jsonl(input).expect("codex jsonl should parse");
        assert_eq!(parsed.source.as_deref(), Some("codex"));
        assert_eq!(parsed.source_session_id.as_deref(), Some("codex-session-1"));
        assert_eq!(parsed.messages.len(), 2);
        assert_eq!(parsed.messages[0].role, ConversationRole::User);
        assert!(parsed.messages[1]
            .content
            .contains("/v1/conversations/search"));
    }

    #[test]
    fn parses_chatgpt_export_mapping() {
        let input = json!({
            "id": "chatgpt-session-1",
            "title": "Conversation import",
            "mapping": {
                "a": {
                    "message": {
                        "author": { "role": "user" },
                        "content": { "parts": ["Please add a ChatGPT importer."] },
                        "create_time": 1
                    }
                },
                "b": {
                    "message": {
                        "author": { "role": "assistant" },
                        "content": { "parts": ["Next step: parse mapping nodes."] },
                        "create_time": 2
                    }
                }
            }
        });
        let parsed = parse_chatgpt_export_value(&input).expect("chatgpt export should parse");
        assert_eq!(parsed.source.as_deref(), Some("chatgpt"));
        assert_eq!(parsed.title.as_deref(), Some("Conversation import"));
        assert_eq!(parsed.messages.len(), 2);
        assert_eq!(parsed.messages[0].role, ConversationRole::User);
        assert!(parsed.messages[1].content.contains("mapping nodes"));
    }

    #[test]
    fn plain_text_role_detection_does_not_slice_through_utf8() {
        let parsed =
            parse_plain_text_transcript("— release note").expect("plain text should parse");
        assert_eq!(parsed.messages.len(), 1);
        assert_eq!(parsed.messages[0].role, ConversationRole::User);
        assert_eq!(parsed.messages[0].content, "— release note");
    }
}
