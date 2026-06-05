use super::*;

#[derive(Debug, Clone)]
pub(super) struct ClientTranscriptCandidate {
    pub(super) source: String,
    pub(super) adapter_kind: String,
    pub(super) path: PathBuf,
    pub(super) format: Option<ConversationImportFormat>,
}

pub(super) fn collect_client_transcript_candidates(
    config: &MemoryPersonalPreferencesConfig,
    limit: usize,
) -> Result<Vec<ClientTranscriptCandidate>> {
    let mut roots = config
        .client_transcript_roots
        .iter()
        .filter_map(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(PathBuf::from(trimmed))
            }
        })
        .collect::<Vec<_>>();
    if roots.is_empty() {
        roots.extend(default_client_transcript_roots());
    }
    let mut candidates = Vec::<(std::time::SystemTime, ClientTranscriptCandidate)>::new();
    for root in roots {
        if !root.exists() {
            continue;
        }
        for entry in WalkDir::new(&root)
            .max_depth(6)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            if !looks_like_transcript_file(path) {
                continue;
            }
            let source = infer_transcript_source(path).unwrap_or_else(|| "manual".to_string());
            if !is_supported_client_transcript_source(&source) {
                continue;
            }
            let adapter_kind = infer_transcript_adapter_kind(&source, path);
            let metadata = entry.metadata().ok();
            let modified = metadata
                .as_ref()
                .and_then(|item| item.modified().ok())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            let format = infer_transcript_format(path, &source);
            candidates.push((
                modified,
                ClientTranscriptCandidate {
                    source,
                    adapter_kind,
                    path: path.to_path_buf(),
                    format,
                },
            ));
        }
    }
    candidates.sort_by(|left, right| right.0.cmp(&left.0));
    candidates.truncate(limit.max(1));
    Ok(candidates
        .into_iter()
        .map(|(_, candidate)| candidate)
        .collect())
}

fn default_client_transcript_roots() -> Vec<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("~"));
    vec![
        home.join(".codex").join("sessions"),
        home.join(".claude").join("projects"),
        home.join(".gemini"),
        home.join(".gemini-cli"),
        home.join(".mcoda").join("conversations"),
    ]
}

fn looks_like_transcript_file(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    let file_name = file_name.to_ascii_lowercase();
    if matches!(
        file_name.as_str(),
        "logs.json" | "conversation.json" | "session.json" | "transcript.json"
    ) {
        return true;
    }
    path.extension()
        .and_then(|value| value.to_str())
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "json" | "jsonl" | "md" | "txt" | "log"
            )
        })
        .unwrap_or(false)
}

fn infer_transcript_source(path: &Path) -> Option<String> {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    for candidate in ["codex", "claude", "gemini", "mcoda", "chatgpt", "openai"] {
        if lower.contains(candidate) {
            return Some(candidate.to_string());
        }
    }
    None
}

fn infer_transcript_adapter_kind(source: &str, path: &Path) -> String {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    match source {
        "codex" => "codex".to_string(),
        "claude" => "claude".to_string(),
        "gemini" => "gemini".to_string(),
        "mcoda" => "mcoda".to_string(),
        "openai" | "chatgpt" => "openai".to_string(),
        _ if lower.contains("codex") => "codex".to_string(),
        _ if lower.contains("claude") => "claude".to_string(),
        _ if lower.contains("gemini") => "gemini".to_string(),
        _ if lower.contains("mcoda") => "mcoda".to_string(),
        _ if lower.contains("openai") || lower.contains("chatgpt") => "openai".to_string(),
        _ => "generic".to_string(),
    }
}

fn infer_transcript_format(path: &Path, source: &str) -> Option<ConversationImportFormat> {
    let ext = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase());
    match (source, ext.as_deref()) {
        ("codex", Some("jsonl")) => Some(ConversationImportFormat::CodexJsonl),
        ("claude", Some("jsonl")) => Some(ConversationImportFormat::ClaudeJsonl),
        ("chatgpt", Some("json")) => Some(ConversationImportFormat::ChatgptExport),
        (_, Some("txt" | "md" | "log")) => Some(ConversationImportFormat::PlainText),
        (_, Some("json")) => Some(ConversationImportFormat::GenericJson),
        (_, Some("jsonl")) => Some(ConversationImportFormat::Auto),
        _ => Some(ConversationImportFormat::Auto),
    }
}

pub(super) fn load_transcript_candidate_imports(
    candidate: &ClientTranscriptCandidate,
) -> Result<Vec<ConversationImport>> {
    let raw = fs::read_to_string(&candidate.path)
        .with_context(|| format!("read transcript {}", candidate.path.display()))?;
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    match candidate.adapter_kind.as_str() {
        "gemini" => {
            if let Ok(imports) = load_gemini_transcript_imports(candidate, &raw) {
                if !imports.is_empty() {
                    return Ok(imports);
                }
            }
        }
        "codex" | "claude" | "mcoda" | "openai" | "generic" => {}
        _ => {}
    }
    let envelope = ConversationImportEnvelope {
        source: Some(candidate.source.clone()),
        source_session_id: None,
        title: candidate
            .path
            .file_stem()
            .and_then(|value| value.to_str())
            .map(ToOwned::to_owned),
        agent_id: None,
        transport: Some("client_transcript_scan".to_string()),
        started_at_ms: None,
        ended_at_ms: None,
        format: candidate.format.map(|value| value.as_str().to_string()),
        messages: None,
        transcript_text: Some(raw),
        metadata: json!({}),
    };
    let import = normalize_import_request(envelope).map_err(|err| anyhow!(err))?;
    Ok(vec![import])
}

fn load_gemini_transcript_imports(
    candidate: &ClientTranscriptCandidate,
    raw: &str,
) -> Result<Vec<ConversationImport>> {
    let value: Value = serde_json::from_str(raw)
        .with_context(|| format!("parse gemini transcript {}", candidate.path.display()))?;
    let sessions = match &value {
        Value::Array(items)
            if items.iter().all(|item| {
                item.get("messages").is_some()
                    || item.get("contents").is_some()
                    || item.get("history").is_some()
            }) =>
        {
            items.clone()
        }
        _ => vec![value],
    };
    let mut imports = Vec::new();
    for session in sessions {
        let Some(messages_value) = session
            .get("messages")
            .or_else(|| session.get("contents"))
            .or_else(|| session.get("history"))
        else {
            continue;
        };
        let messages = gemini_messages_from_value(messages_value);
        if messages.is_empty() {
            continue;
        }
        let source_session_id = first_text_from_value(
            &session,
            &["source_session_id", "session_id", "id", "conversation_id"],
        );
        let title = first_text_from_value(&session, &["title", "name"]);
        imports.push(ConversationImport {
            source: candidate.source.clone(),
            source_session_id,
            title,
            agent_id: None,
            transport: Some("client_transcript_scan".to_string()),
            started_at_ms: None,
            ended_at_ms: None,
            messages,
            metadata: object_or_empty_for_personal_preferences(session),
        });
    }
    Ok(imports)
}

fn gemini_messages_from_value(value: &Value) -> Vec<ConversationMessage> {
    let Some(items) = value.as_array() else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let role = item
                .get("role")
                .and_then(Value::as_str)
                .or_else(|| item.get("author").and_then(Value::as_str))
                .unwrap_or("other");
            let content = item
                .get("parts")
                .and_then(Value::as_array)
                .map(|parts| {
                    parts
                        .iter()
                        .filter_map(|part| {
                            part.get("text")
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned)
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                })
                .filter(|text| !text.trim().is_empty())
                .or_else(|| {
                    item.get("content")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                })
                .or_else(|| {
                    item.get("text")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                })?;
            Some(ConversationMessage {
                role: crate::conversations::ConversationRole::from_str(role),
                content: content.trim().to_string(),
                author: item
                    .get("author")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                created_at_ms: parse_timestamp_json_value(
                    item.get("created_at_ms")
                        .or_else(|| item.get("created_at"))
                        .or_else(|| item.get("timestamp")),
                ),
                metadata: object_or_empty_for_personal_preferences(item.clone()),
            })
        })
        .filter(|message| !message.content.is_empty())
        .collect()
}

pub(super) fn capture_request_from_import(
    candidate: &ClientTranscriptCandidate,
    import: ConversationImport,
) -> PersonalPreferencesCaptureRequest {
    let messages = import
        .messages
        .into_iter()
        .map(|message| PersonalPreferencesMessage {
            role: message.role.as_str().to_string(),
            content: message.content,
            created_at_ms: message.created_at_ms,
            metadata: message.metadata,
        })
        .collect::<Vec<_>>();
    let transcript_text = if messages.is_empty() {
        None
    } else {
        Some(
            messages
                .iter()
                .map(|message| format!("{}: {}", message.role, message.content.trim()))
                .collect::<Vec<_>>()
                .join("\n"),
        )
    };
    let mut metadata = import.metadata.as_object().cloned().unwrap_or_default();
    metadata.insert(
        "client_transcript_path".to_string(),
        Value::String(candidate.path.display().to_string()),
    );
    metadata.insert(
        "client_transcript_source".to_string(),
        Value::String(candidate.source.clone()),
    );
    metadata.insert(
        "client_transcript_adapter".to_string(),
        Value::String(candidate.adapter_kind.clone()),
    );
    metadata.insert(
        "client_transcript_format".to_string(),
        Value::String(
            candidate
                .format
                .unwrap_or(ConversationImportFormat::Auto)
                .as_str()
                .to_string(),
        ),
    );
    metadata.insert(
        "external_ref".to_string(),
        Value::String(format!(
            "{}:{}",
            candidate.path.display(),
            import
                .source_session_id
                .clone()
                .or_else(|| import.title.clone())
                .unwrap_or_else(|| "session".to_string())
        )),
    );
    PersonalPreferencesCaptureRequest {
        source: candidate.source.clone(),
        source_session_id: import.source_session_id,
        capture_kind: Some("client_transcript_scan".to_string()),
        title: import.title,
        agent_id: import.agent_id,
        transport: Some("client_transcript_scan".to_string()),
        repo_id: None,
        repo_root: None,
        scope_id: Some(format!(
            "client_transcript:{}",
            slugify_identifier(&candidate.source)
        )),
        scope_label: Some(candidate.path.display().to_string()),
        started_at_ms: import.started_at_ms,
        ended_at_ms: import.ended_at_ms,
        messages,
        transcript_text,
        summary_text: None,
        metadata: Value::Object(metadata),
    }
}
