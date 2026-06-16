use super::*;

pub async fn process_pending_with_local_agents(
    store: &PersonalPreferencesStore,
    global_state_dir: Option<&Path>,
    llm_config: &LlmConfig,
    config: &MemoryPersonalPreferencesConfig,
    limit: Option<usize>,
) -> Result<PersonalPreferencesProcessingSummary> {
    if !config.digest_enabled {
        return Ok(PersonalPreferencesProcessingSummary::default());
    }
    let batch_limit = limit
        .filter(|value| *value > 0)
        .map(|value| value.min(512))
        .unwrap_or_else(|| config.max_parallel_digest_jobs.max(1));
    let mut effective_llm_config = llm_config.clone();
    effective_llm_config.delegation.cloud.enabled = false;
    effective_llm_config.delegation.cloud_agent_id.clear();
    effective_llm_config.delegation.code.cloud_agent_id.clear();
    effective_llm_config
        .delegation
        .general
        .cloud_agent_id
        .clear();
    let library = match refresh_local_library_if_stale(
        global_state_dir,
        &effective_llm_config,
        false,
    )
    .await
    {
        Ok(library) => library,
        Err(err) => {
            warn!(
                target: "docdexd",
                error = ?err,
                "personal preferences local library refresh failed; falling back to cached library"
            );
            load_local_library(global_state_dir)?
        }
    };
    let mut library = library;
    let mut local_targets = build_local_target_candidates_with_config(
        global_state_dir,
        &effective_llm_config,
        TaskType::GeneralQuestion,
        &mut library,
    );
    if config.digest_with_local_mcoda_only {
        local_targets.retain(|target| match target {
            LocalTarget::McodaAgent(agent_id) => library
                .agents
                .iter()
                .find(|entry| entry.agent_id == *agent_id)
                .map(|entry| !local_agent_is_cloud(entry))
                .unwrap_or(false),
            LocalTarget::LocalServiceModel { .. } => false,
            LocalTarget::OllamaModel(_) => false,
        });
    }
    let local_targets = std::sync::Arc::new(local_targets);
    let effective_config = config.clone();
    let state_dir = global_state_dir.map(PathBuf::from);
    store
        .process_pending_with_runner(batch_limit, move |input| {
            let local_targets = local_targets.clone();
            let llm_config = effective_llm_config.clone();
            let state_dir = state_dir.clone();
            let effective_config = effective_config.clone();
            async move {
                if should_use_heuristic_digest(&input.capture) {
                    return Ok(Some(heuristic_digest_output(&input.capture)));
                }
                if local_targets.is_empty() {
                    return Ok(None);
                }
                let completion = run_delegation_flow_with_failure_history(
                    &llm_config,
                    None,
                    local_targets.as_ref(),
                    &[],
                    TaskType::GeneralQuestion,
                    &build_digest_instruction(&input.capture),
                    &build_digest_context(&input.capture, &effective_config),
                    llm_config.delegation.max_context_chars.min(64_000),
                    None,
                    Some(
                        llm_config
                            .delegation
                            .timeout_ms
                            .min(PERSONAL_PREFERENCES_DIGEST_TIMEOUT_CAP_MS),
                    ),
                    DelegationMode::DraftOnly,
                    Some(DelegationFailureHistoryContext {
                        global_state_dir: state_dir.clone(),
                        repo_id: input.capture.repo_id.clone(),
                        repo_root: input.capture.repo_root.clone(),
                        source: Some("personal_preferences".to_string()),
                    }),
                )
                .await?;
                match parse_digest_output(&completion.completion.output) {
                    Ok(output) => Ok(Some(output)),
                    Err(parse_err) => {
                        let parse_err_text = parse_err.to_string();
                        warn!(
                            target: "docdexd",
                            capture_id = %input.capture.id,
                            error = %parse_err_text,
                            "personal preferences digest output failed JSON parse; attempting local repair"
                        );
                        let repair_instruction = build_digest_repair_instruction(&input.capture);
                        let repair_context =
                            build_digest_repair_context(&completion.completion.output);
                        let repair_result = run_delegation_flow_with_failure_history(
                            &llm_config,
                            None,
                            local_targets.as_ref(),
                            &[],
                            TaskType::GeneralQuestion,
                            &repair_instruction,
                            &repair_context,
                            llm_config.delegation.max_context_chars.min(64_000),
                            None,
                            Some(
                                llm_config
                                    .delegation
                                    .timeout_ms
                                    .min(PERSONAL_PREFERENCES_DIGEST_TIMEOUT_CAP_MS),
                            ),
                            DelegationMode::DraftOnly,
                            Some(DelegationFailureHistoryContext {
                                global_state_dir: state_dir,
                                repo_id: input.capture.repo_id.clone(),
                                repo_root: input.capture.repo_root.clone(),
                                source: Some("personal_preferences_repair".to_string()),
                            }),
                        )
                        .await;
                        match repair_result {
                            Ok(repair_completion) => {
                                match parse_digest_output(&repair_completion.completion.output) {
                                    Ok(repaired) => Ok(Some(repaired)),
                                    Err(repair_err) => {
                                        warn!(
                                            target: "docdexd",
                                            capture_id = %input.capture.id,
                                            error = ?repair_err,
                                            "personal preferences digest repair output failed JSON parse; using heuristic fallback"
                                        );
                                        Ok(Some(heuristic_digest_output(&input.capture)))
                                    }
                                }
                            }
                            Err(repair_err) => {
                                warn!(
                                    target: "docdexd",
                                    capture_id = %input.capture.id,
                                    error = ?repair_err,
                                    "personal preferences digest repair delegation failed; using heuristic fallback"
                                );
                                Ok(Some(heuristic_digest_output(&input.capture)))
                            }
                        }
                    }
                }
            }
        })
        .await
}

pub async fn project_safe_preferences_to_profile(
    store: &PersonalPreferencesStore,
    manager: &ProfileManager,
    embedder: Option<&ProfileEmbedder>,
    config: &MemoryPersonalPreferencesConfig,
    default_agent_id: Option<&str>,
) -> Result<usize> {
    if !config.auto_project_safe_preferences_to_profile {
        return Ok(0);
    }
    let Some(embedder) = embedder else {
        return Ok(0);
    };
    let mut projected = 0usize;
    let mut projected_record_ids = Vec::new();
    let mut ensured_agents = HashSet::new();
    let records = store.list_projectable_records(MAX_PROJECTABLE_RECORDS)?;
    for record in records {
        let Some(category) = map_record_to_profile_category(&record) else {
            continue;
        };
        let content = format!("[personal_preferences] {}", render_record(&record));
        let agent_id = record_agent_id(&record)
            .or_else(|| default_agent_id.map(ToOwned::to_owned))
            .unwrap_or_else(|| "default".to_string());
        if ensured_agents.insert(agent_id.clone()) && manager.get_agent(&agent_id)?.is_none() {
            manager.create_agent(&agent_id, "personal_preferences", now_ms())?;
        }
        let embedding = embedder.embed_with_metadata(&content).await?;
        manager.add_preference_with_embedding_metadata(
            &agent_id,
            &content,
            &embedding.embedding,
            category,
            now_ms(),
            Some(&embedding.provider),
            Some(&embedding.model),
        )?;
        projected_record_ids.push(record.id);
        projected += 1;
    }
    store.mark_records_projected(&projected_record_ids)?;
    Ok(projected)
}

pub fn extract_digest_output(text: &str) -> Result<PersonalPreferenceDigestOutput> {
    parse_digest_output(text)
}

pub fn status_payload_with_config(
    status: PersonalPreferenceStatus,
    config: &MemoryPersonalPreferencesConfig,
) -> Result<Value> {
    let mut value = serde_json::to_value(status)?;
    if let Value::Object(map) = &mut value {
        let transcript_autopilot_enabled = config.capture_enabled
            && config.capture_supported_client_transcripts
            && config.process_in_background;
        let digest_autopilot_enabled = config.digest_enabled && config.process_in_background;
        let freshness_risk = config.enabled
            && config.capture_enabled
            && (config.capture_supported_client_transcripts || config.digest_enabled)
            && !config.process_in_background;
        map.insert(
            "automation".to_string(),
            json!({
                "capture_enabled": config.capture_enabled,
                "capture_supported_client_transcripts": config.capture_supported_client_transcripts,
                "digest_enabled": config.digest_enabled,
                "process_in_background": config.process_in_background,
                "transcript_autopilot_enabled": transcript_autopilot_enabled,
                "digest_autopilot_enabled": digest_autopilot_enabled,
                "freshness_risk": freshness_risk,
            }),
        );
    }
    Ok(value)
}

pub fn is_supported_client_transcript_source(source: &str) -> bool {
    let normalized = slugify_identifier(source);
    if normalized.is_empty() {
        return false;
    }
    [
        "codex",
        "codex_cli",
        "claude",
        "claude_cli",
        "claude_code",
        "gemini",
        "gemini_cli",
        "openai",
        "openai_cli",
        "cursor",
        "zed",
        "copilot",
        "mcoda",
    ]
    .iter()
    .any(|item| normalized == *item || normalized.starts_with(&format!("{item}_")))
}

pub fn should_capture_external_source(
    config: &MemoryPersonalPreferencesConfig,
    source: &str,
    explicit_capture_enabled: bool,
) -> bool {
    config.capture_enabled
        && config.allows_source(source)
        && (explicit_capture_enabled
            || (config.capture_supported_client_transcripts
                && is_supported_client_transcript_source(source)))
}

fn build_digest_instruction(capture: &PersonalPreferencesCaptureRecord) -> String {
    let categories = DEFAULT_CATEGORY_POLICIES
        .iter()
        .map(|policy| format!("- {}: {}", policy.category, policy.description))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "You are extracting durable personal-profile knowledge about a local user from a conversation transcript.\n\
Extract only durable user-specific signals that would help future agents work in the user's preferred style.\n\
Focus on the user's preferences, methods, goals, communication style, projects, personality, business context, personal context, likes/dislikes, strengths, constraints, and cross-project bridges.\n\
Do not include secrets, credentials, API keys, one-time codes, agent instructions, system/developer prompts, or transient single-turn details.\n\
Use these suggested categories when possible:\n{categories}\n\
The context contains user-authored messages only, plus capture metadata.\n\
Return JSON only with this exact shape:\n\
{{\"records\":[{{\"record_type\":\"preference\",\"category\":\"coding_preference\",\"subcategory\":\"rust\",\"subject\":\"user\",\"attribute\":\"prefers\",\"value\":\"Rust\",\"confidence\":0.92,\"sensitivity\":\"low\",\"evidence\":\"short quote or paraphrase\",\"metadata\":{{}}}}]}}\n\
Rules:\n\
- At most {MAX_DIGEST_RECORDS_PER_CAPTURE} records.\n\
- `record_type` should be one of preference, method, goal, project, trait, capability, context, like, dislike, bridge, or other.\n\
- `confidence` must be 0.0-1.0.\n\
- `sensitivity` must be low, private, sensitive, or special.\n\
- `subject` should usually be `user` unless the user explicitly frames another enduring subject.\n\
- Skip anything speculative, contradictory, or too weak.\n\
- The conversation capture id is {}.",
        capture.id
    )
}

pub(super) fn build_digest_context(
    capture: &PersonalPreferencesCaptureRecord,
    config: &MemoryPersonalPreferencesConfig,
) -> String {
    let mut parts = Vec::new();
    parts.push(format!("source: {}", capture.source));
    if let Some(value) = capture.capture_kind.as_deref() {
        parts.push(format!("capture_kind: {value}"));
    }
    if let Some(value) = capture.repo_root.as_deref() {
        parts.push(format!("repo_root: {value}"));
    }
    if let Some(value) = capture.scope_label.as_deref() {
        parts.push(format!("scope_label: {value}"));
    }
    if let Some(value) = capture.title.as_deref() {
        parts.push(format!("title: {value}"));
    }
    if let Some(value) = capture.agent_id.as_deref() {
        parts.push(format!("agent_id: {value}"));
    }
    parts.push(format!(
        "archive_raw_conversations: {}",
        config.archive_raw_conversations
    ));
    let user_messages = digest_user_message_blocks(capture);
    if !user_messages.is_empty() {
        parts.push("user_messages:".to_string());
        for message in user_messages {
            parts.push(format!("- {message}"));
        }
    } else if !capture.transcript_text.trim().is_empty() {
        parts.push("transcript_excerpt:".to_string());
        parts.push(truncate_chars(
            capture.transcript_text.trim(),
            MAX_DIGEST_CONTEXT_CHARS / 2,
        ));
    }
    truncate_chars(&parts.join("\n"), MAX_DIGEST_CONTEXT_CHARS)
}

fn digest_user_message_blocks(capture: &PersonalPreferencesCaptureRecord) -> Vec<String> {
    let mut blocks = Vec::new();
    for message in &capture.messages {
        if !is_user_digest_role(&message.role) {
            continue;
        }
        let content = normalize_text(message.content.trim());
        if content.is_empty() {
            continue;
        }
        blocks.push(format!(
            "{}: {}",
            normalize_text(&message.role),
            truncate_chars(&content, MAX_DIGEST_USER_MESSAGE_CHARS)
        ));
        if blocks.len() >= MAX_DIGEST_USER_MESSAGES {
            return blocks;
        }
    }
    if blocks.is_empty() {
        blocks = extract_user_blocks_from_transcript(&capture.transcript_text);
    }
    blocks.truncate(MAX_DIGEST_USER_MESSAGES);
    blocks
}

fn extract_user_blocks_from_transcript(text: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current_role = String::new();
    let mut current_content = String::new();
    for line in text.lines() {
        if let Some((role, content)) = transcript_role_line(line) {
            push_digest_user_block(&mut blocks, &current_role, &current_content);
            current_role = role.to_string();
            current_content = if is_user_digest_role(&current_role) {
                content.trim().to_string()
            } else {
                String::new()
            };
            continue;
        }
        if is_user_digest_role(&current_role) {
            if !current_content.is_empty() {
                current_content.push('\n');
            }
            current_content.push_str(line);
        }
    }
    push_digest_user_block(&mut blocks, &current_role, &current_content);
    blocks
}

fn push_digest_user_block(blocks: &mut Vec<String>, role: &str, content: &str) {
    if blocks.len() >= MAX_DIGEST_USER_MESSAGES || !is_user_digest_role(role) {
        return;
    }
    let content = normalize_text(content.trim());
    if content.is_empty() {
        return;
    }
    blocks.push(format!(
        "{}: {}",
        normalize_text(role),
        truncate_chars(&content, MAX_DIGEST_USER_MESSAGE_CHARS)
    ));
}

fn transcript_role_line(line: &str) -> Option<(&str, &str)> {
    let trimmed = line.trim_start();
    let (role, content) = trimmed.split_once(':')?;
    let normalized = role.trim().to_ascii_lowercase();
    if matches!(
        normalized.as_str(),
        "user"
            | "human"
            | "assistant"
            | "developer"
            | "system"
            | "tool"
            | "function"
            | "analysis"
            | "commentary"
            | "final"
    ) {
        Some((role.trim(), content))
    } else {
        None
    }
}

fn is_user_digest_role(role: &str) -> bool {
    matches!(role.trim().to_ascii_lowercase().as_str(), "user" | "human")
}

pub(super) fn heuristic_digest_output(
    capture: &PersonalPreferencesCaptureRecord,
) -> PersonalPreferenceDigestOutput {
    let blocks = digest_user_message_blocks(capture);
    let joined = blocks.join("\n");
    let normalized = joined.to_ascii_lowercase();
    let mut records = Vec::new();
    let mut seen = HashSet::<&'static str>::new();

    maybe_push_heuristic_digest_record(
        &mut records,
        &mut seen,
        &normalized,
        &joined,
        "progress_markdown",
        &["progress"],
        &["markdown", ".md", "md file"],
        "method",
        "documentation_preference",
        "tracking",
        "keeps_progress_in_markdown",
        "Keep implementation progress in a separate markdown file.",
    );
    maybe_push_heuristic_digest_record(
        &mut records,
        &mut seen,
        &normalized,
        &joined,
        "plan_first",
        &["plan"],
        &["implementation", "working", "start", "first"],
        "method",
        "workflow_method",
        "planning",
        "plans_before_work",
        "Create or revisit a plan before substantial implementation.",
    );
    maybe_push_heuristic_digest_record(
        &mut records,
        &mut seen,
        &normalized,
        &joined,
        "repo_inspection",
        &["codebase", "repo", "repository"],
        &["inspect", "compare", "review", "search"],
        "method",
        "workflow_method",
        "repo_truth",
        "inspects_repo_before_changes",
        "Inspect the real codebase and compare it with the plan before changing behavior.",
    );
    maybe_push_heuristic_digest_record(
        &mut records,
        &mut seen,
        &normalized,
        &joined,
        "run_tests",
        &["test", "tests", "validation", "validate"],
        &[],
        "method",
        "testing_preference",
        "validation",
        "runs_tests",
        "Run targeted validation before considering work complete.",
    );
    maybe_push_heuristic_digest_record(
        &mut records,
        &mut seen,
        &normalized,
        &joined,
        "complete_end_to_end",
        &["do not stop", "complete", "finish"],
        &["all", "until", "end"],
        "preference",
        "workflow_method",
        "completion",
        "prefers_end_to_end_completion",
        "Prefer agents to continue until the requested work is genuinely complete.",
    );
    maybe_push_heuristic_digest_record(
        &mut records,
        &mut seen,
        &normalized,
        &joined,
        "git_commit",
        &["git", "commit", "push"],
        &[],
        "method",
        "delivery_preference",
        "git",
        "uses_git_after_validation",
        "Use git commits and pushes deliberately after validation when appropriate.",
    );
    maybe_push_heuristic_digest_record(
        &mut records,
        &mut seen,
        &normalized,
        &joined,
        "deploy_safely",
        &["deploy", "production", "prod"],
        &["validate", "test", "backup", "smoke", "verify"],
        "method",
        "deployment_method",
        "release_safety",
        "validates_deployments",
        "Treat production/deployment work as requiring validation and explicit checks.",
    );
    maybe_push_heuristic_digest_record(
        &mut records,
        &mut seen,
        &normalized,
        &joined,
        "backup_first",
        &["backup", "rollback"],
        &[],
        "method",
        "deployment_method",
        "rollback",
        "backs_up_before_risk",
        "Prefer backup or rollback awareness before risky production changes.",
    );
    maybe_push_heuristic_digest_record(
        &mut records,
        &mut seen,
        &normalized,
        &joined,
        "docdex_graph",
        &["docdex"],
        &["impact", "dag", "symbols", "search", "memory"],
        "method",
        "tooling_preference",
        "docdex",
        "uses_docdex_code_intelligence",
        "Use Docdex memory, search, symbols, impact graph, or DAG tooling when it improves agent work.",
    );

    records.truncate(MAX_DIGEST_RECORDS_PER_CAPTURE);
    PersonalPreferenceDigestOutput { records }
}

pub(super) fn should_use_heuristic_digest(capture: &PersonalPreferencesCaptureRecord) -> bool {
    if capture.capture_kind.as_deref() == Some("client_transcript_scan") {
        return true;
    }
    capture
        .metadata
        .get("client_transcript_adapter")
        .and_then(Value::as_str)
        .map(is_supported_client_transcript_source)
        .unwrap_or(false)
}

#[allow(clippy::too_many_arguments)]
fn maybe_push_heuristic_digest_record(
    records: &mut Vec<PersonalPreferenceDigestRecord>,
    seen: &mut HashSet<&'static str>,
    normalized_text: &str,
    evidence_text: &str,
    key: &'static str,
    required_terms: &[&str],
    secondary_terms: &[&str],
    record_type: &str,
    category: &str,
    subcategory: &str,
    attribute: &str,
    value: &str,
) {
    if seen.contains(key)
        || !terms_match(normalized_text, required_terms)
        || (!secondary_terms.is_empty() && !terms_match(normalized_text, secondary_terms))
    {
        return;
    }
    seen.insert(key);
    records.push(PersonalPreferenceDigestRecord {
        record_type: record_type.to_string(),
        category: category.to_string(),
        subcategory: Some(subcategory.to_string()),
        subject: "user".to_string(),
        attribute: Some(attribute.to_string()),
        value: value.to_string(),
        confidence: Some(0.74),
        sensitivity: Some("low".to_string()),
        evidence: Some(truncate_chars(evidence_text, MAX_DIGEST_EVIDENCE_CHARS)),
        metadata: json!({ "extractor": "heuristic_fallback" }),
    });
}

fn terms_match(text: &str, terms: &[&str]) -> bool {
    terms.is_empty() || terms.iter().any(|term| text.contains(term))
}

fn build_digest_repair_instruction(capture: &PersonalPreferencesCaptureRecord) -> String {
    format!(
        "Repair a malformed personal-preferences digest for capture {}.\n\
Return JSON only with this exact shape: {{\"records\":[...]}}.\n\
Use only durable records already present in the malformed output. Do not add new facts from memory, do not infer missing facts, and do not include markdown, reasoning, comments, or prose.\n\
If the malformed output contains no usable durable records, return {{\"records\":[]}}.\n\
Each record must preserve the personal-preferences schema fields when available: record_type, category, subcategory, subject, attribute, value, confidence, sensitivity, evidence, metadata.",
        capture.id
    )
}

fn build_digest_repair_context(malformed_output: &str) -> String {
    format!(
        "malformed_digest_output:\n{}",
        truncate_chars(malformed_output, 60_000)
    )
}

pub(super) fn parse_digest_output(text: &str) -> Result<PersonalPreferenceDigestOutput> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(PersonalPreferenceDigestOutput::default());
    }
    let mut candidates = Vec::<String>::new();
    push_digest_parse_candidate(&mut candidates, trimmed);
    push_digest_parse_candidate(
        &mut candidates,
        trimmed
            .strip_prefix("```json")
            .and_then(|value| value.strip_suffix("```"))
            .map(str::trim)
            .unwrap_or(trimmed),
    );
    push_digest_parse_candidate(
        &mut candidates,
        trimmed
            .strip_prefix("```")
            .and_then(|value| value.strip_suffix("```"))
            .map(str::trim)
            .unwrap_or(trimmed),
    );
    for candidate in extract_balanced_json_candidates(trimmed).into_iter().rev() {
        push_digest_parse_candidate(&mut candidates, candidate);
        if let Some(records_candidate) = extract_records_assignment_candidate(candidate) {
            push_digest_parse_candidate(&mut candidates, records_candidate);
        }
    }
    if let Some(candidate) = extract_records_assignment_candidate(trimmed) {
        push_digest_parse_candidate(&mut candidates, candidate);
    }

    let mut shape_error = None;
    for candidate in &candidates {
        if candidate.trim().is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(candidate) {
            match parse_digest_value(&value) {
                Ok(output) => return Ok(output),
                Err(err) => shape_error = Some(err.to_string()),
            }
        }
    }
    if let Some(err) = shape_error {
        return Err(anyhow!(err));
    }
    Err(anyhow!("digest output was not valid JSON"))
}

fn parse_digest_value(value: &Value) -> Result<PersonalPreferenceDigestOutput> {
    if let Some(text) = value.as_str() {
        return parse_digest_output(text);
    }
    if let Some(records) = value.get("records").and_then(Value::as_array) {
        let mut out = Vec::new();
        for record in records {
            if let Ok(parsed) =
                serde_json::from_value::<PersonalPreferenceDigestRecord>(record.clone())
            {
                out.push(parsed);
            }
        }
        return Ok(PersonalPreferenceDigestOutput { records: out });
    }
    if let Some(records_text) = value.get("records").and_then(Value::as_str) {
        return parse_digest_output(records_text);
    }
    if let Some(records) = value.as_array() {
        let mut out = Vec::new();
        for record in records {
            if let Ok(parsed) =
                serde_json::from_value::<PersonalPreferenceDigestRecord>(record.clone())
            {
                out.push(parsed);
            }
        }
        return Ok(PersonalPreferenceDigestOutput { records: out });
    }
    if let Ok(record) = serde_json::from_value::<PersonalPreferenceDigestRecord>(value.clone()) {
        return Ok(PersonalPreferenceDigestOutput {
            records: vec![record],
        });
    }
    if let Some(text) = extract_digest_text_from_envelope(value) {
        return parse_digest_output(&text);
    }
    Err(anyhow!("digest JSON did not contain a records array"))
}

fn push_digest_parse_candidate(candidates: &mut Vec<String>, candidate: impl AsRef<str>) {
    let candidate = candidate.as_ref().trim();
    if candidate.is_empty() {
        return;
    }
    if candidates.iter().any(|item| item == candidate) {
        return;
    }
    candidates.push(candidate.to_string());
}

fn extract_digest_text_from_envelope(value: &Value) -> Option<String> {
    let object = value.as_object()?;
    for key in [
        "output",
        "text",
        "content",
        "completion",
        "response",
        "result",
    ] {
        if let Some(text) = object
            .get(key)
            .and_then(Value::as_str)
            .and_then(normalize_non_empty_text)
        {
            return Some(text);
        }
    }
    if let Some(message_content) = object
        .get("message")
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .and_then(normalize_non_empty_text)
    {
        return Some(message_content);
    }
    let choices = object.get("choices")?.as_array()?;
    for choice in choices {
        if let Some(text) = choice
            .get("message")
            .and_then(|message| message.get("content"))
            .and_then(Value::as_str)
            .and_then(normalize_non_empty_text)
            .or_else(|| {
                choice
                    .get("text")
                    .and_then(Value::as_str)
                    .and_then(normalize_non_empty_text)
            })
            .or_else(|| {
                choice
                    .get("content")
                    .and_then(Value::as_str)
                    .and_then(normalize_non_empty_text)
            })
        {
            return Some(text);
        }
    }
    None
}

fn extract_records_assignment_candidate(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let mut search_start = 0usize;
    while let Some(relative_idx) = lower[search_start..].find("records") {
        let record_idx = search_start + relative_idx;
        let after_record = record_idx + "records".len();
        let Some(array_relative_idx) = lower[after_record..].find('[') else {
            return None;
        };
        let array_start = after_record + array_relative_idx;
        if lower[after_record..array_start]
            .chars()
            .any(|ch| !(ch.is_ascii_whitespace() || matches!(ch, ':' | '=' | '"')))
        {
            search_start = after_record;
            continue;
        }
        if let Some(array) = extract_balanced_json_candidate_from(text, array_start) {
            return Some(format!("{{\"records\":{array}}}"));
        }
        search_start = after_record;
    }
    None
}

#[derive(Debug, Default)]
struct DigestFailureAccumulator {
    count: usize,
    latest_error: Option<String>,
    latest_at_ms: Option<i64>,
}

pub(super) fn load_digest_failure_breakdown(
    conn: &Connection,
) -> Result<Vec<PersonalPreferenceDigestFailureGroup>> {
    let mut stmt = conn.prepare(
        "SELECT source, capture_kind, last_digest_error, updated_at_ms
         FROM captured_conversations
         WHERE digest_status = 'failed'",
    )?;
    let mut rows = stmt.query([])?;
    let mut groups = BTreeMap::<(String, String, String), DigestFailureAccumulator>::new();
    while let Some(row) = rows.next()? {
        let source = normalize_failure_group_value(row.get::<_, String>(0)?);
        let capture_kind =
            normalize_failure_group_value(row.get::<_, Option<String>>(1)?.unwrap_or_default());
        let error = row.get::<_, Option<String>>(2)?.unwrap_or_default();
        let updated_at_ms = row.get::<_, i64>(3)?;
        let failure_class = classify_digest_failure(&error);
        let entry = groups
            .entry((source, capture_kind, failure_class))
            .or_default();
        entry.count += 1;
        if entry
            .latest_at_ms
            .map(|latest| updated_at_ms >= latest)
            .unwrap_or(true)
        {
            entry.latest_at_ms = Some(updated_at_ms);
            entry.latest_error =
                normalize_non_empty_text(&error).map(|value| truncate_chars(&value, 240));
        }
    }
    Ok(groups
        .into_iter()
        .map(|((source, capture_kind, failure_class), entry)| {
            PersonalPreferenceDigestFailureGroup {
                source,
                capture_kind,
                failure_class,
                count: entry.count,
                latest_error: entry.latest_error,
                latest_at_ms: entry.latest_at_ms,
            }
        })
        .collect())
}

fn normalize_failure_group_value(value: String) -> String {
    let normalized = slugify_identifier(&value);
    if normalized.is_empty() {
        "unknown".to_string()
    } else {
        normalized
    }
}

fn classify_digest_failure(error: &str) -> String {
    let normalized = error.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return "unknown".to_string();
    }
    if normalized.contains("not valid json")
        || normalized.contains("invalid json")
        || normalized.contains("repair output was also invalid")
        || normalized.contains("json parse")
        || normalized.contains("expected value")
    {
        return "invalid_json".to_string();
    }
    if normalized.contains("records array")
        || normalized.contains("schema")
        || normalized.contains("missing field")
        || normalized.contains("unknown field")
    {
        return "schema_mismatch".to_string();
    }
    if normalized.contains("timed out")
        || normalized.contains("timeout")
        || normalized.contains("deadline")
    {
        return "timeout".to_string();
    }
    if normalized.contains("context length")
        || normalized.contains("context window")
        || normalized.contains("max context")
        || normalized.contains("too large")
        || normalized.contains("token")
    {
        return "context_too_large".to_string();
    }
    if normalized.contains("no local")
        || normalized.contains("waiting_for_local")
        || normalized.contains("no healthy")
    {
        return "no_local_agent".to_string();
    }
    if normalized.contains("delegation")
        || normalized.contains("mcoda")
        || normalized.contains("ollama")
        || normalized.contains("local_completion")
        || normalized.contains("connection refused")
        || normalized.contains("transport")
        || normalized.contains("request")
    {
        return "local_delegation".to_string();
    }
    "processing_error".to_string()
}
