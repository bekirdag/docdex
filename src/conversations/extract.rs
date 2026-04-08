use crate::conversations::types::{
    ConversationDurableMemoryCandidate, ConversationDurableMemoryCategory,
    ConversationDurableMemoryTarget, ConversationMessage, ConversationRole, SessionSummaryRecord,
    WorkingMemoryRecord,
};
use crate::knowledge::{
    extract_entity_hints, infer_fact_shape, normalize_relation_name, KnowledgeGraphCandidate,
};
use serde_json::json;
use std::collections::HashSet;

#[derive(Debug, Clone)]
struct OpenLoopCandidate {
    text: String,
    priority: u8,
    recency_rank: usize,
}

#[derive(Debug, Clone)]
pub struct ExtractedConversationArtifacts {
    pub summary: SessionSummaryRecord,
    pub working_memory: Option<WorkingMemoryRecord>,
    pub durable_memories: Vec<ConversationDurableMemoryCandidate>,
    pub knowledge_graph_candidates: Vec<KnowledgeGraphCandidate>,
}

pub fn extract_session_artifacts(
    session_id: &str,
    title: Option<&str>,
    agent_id: Option<&str>,
    messages: &[ConversationMessage],
    last_message_at_ms: i64,
) -> ExtractedConversationArtifacts {
    let latest_user_goal = find_latest_message(
        messages,
        &[ConversationRole::User, ConversationRole::Developer],
    );
    let latest_assistant_reply = find_latest_message(messages, &[ConversationRole::Assistant]);
    let open_loop_candidates = extract_open_loop_candidates(messages);
    let open_loops = open_loop_candidates
        .iter()
        .map(|item| item.text.clone())
        .collect::<Vec<_>>();
    let participants = collect_participants(messages);
    let next_step = select_next_step(&open_loop_candidates);
    let durable_memories = extract_durable_memory_candidates(messages);
    let knowledge_graph_candidates = extract_knowledge_graph_candidates(
        session_id,
        title,
        agent_id,
        last_message_at_ms,
        &durable_memories,
    );
    let summary = build_summary(
        title,
        latest_user_goal.as_deref(),
        latest_assistant_reply.as_deref(),
        &open_loops,
        messages,
    );
    let summary_record = SessionSummaryRecord {
        session_id: session_id.to_string(),
        title: title
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
        summary,
        open_loops: open_loops.clone(),
        participants,
        latest_user_goal: latest_user_goal.clone(),
        latest_assistant_reply: latest_assistant_reply.clone(),
        last_message_at_ms,
        updated_at_ms: last_message_at_ms,
    };
    let working_memory = if latest_user_goal.is_some() || !open_loops.is_empty() {
        Some(WorkingMemoryRecord {
            agent_id: agent_id
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
            active_objective: latest_user_goal,
            next_step,
            open_loops,
            source_session_id: session_id.to_string(),
            updated_at_ms: last_message_at_ms,
        })
    } else {
        None
    };
    ExtractedConversationArtifacts {
        summary: summary_record,
        working_memory,
        durable_memories,
        knowledge_graph_candidates,
    }
}

fn extract_knowledge_graph_candidates(
    session_id: &str,
    title: Option<&str>,
    agent_id: Option<&str>,
    last_message_at_ms: i64,
    durable_memories: &[ConversationDurableMemoryCandidate],
) -> Vec<KnowledgeGraphCandidate> {
    let mut seen = HashSet::new();
    let mut items = Vec::new();
    for candidate in durable_memories {
        let relation = relation_for_durable_category(&candidate.category);
        let inferred = infer_fact_shape(&candidate.content, relation);
        let inferred_relation = inferred.relation.clone();
        let mut entity_hints = extract_entity_hints(&candidate.content);
        let subject = inferred
            .subject
            .filter(|value| !value.trim().is_empty())
            .or_else(|| entity_hints.first().cloned())
            .or_else(|| {
                title
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned)
            })
            .unwrap_or_else(|| {
                agent_id
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(|value| format!("{value} repo"))
                    .unwrap_or_else(|| "repo".to_string())
            });
        if !entity_hints
            .iter()
            .any(|item| item.eq_ignore_ascii_case(&subject))
        {
            entity_hints.insert(0, subject.clone());
        }
        let summary = canonical_sentence(&inferred.object_text);
        let dedupe_key = format!(
            "{}\n{}\n{}",
            subject.to_ascii_lowercase(),
            normalize_relation_name(&inferred.relation),
            summary.to_ascii_lowercase()
        );
        if !seen.insert(dedupe_key) {
            continue;
        }
        items.push(KnowledgeGraphCandidate {
            subject,
            subject_type_hint: subject_type_hint_for_fact(
                title,
                agent_id,
                &inferred_relation,
                &entity_hints,
            ),
            subject_aliases: Vec::new(),
            relation: inferred_relation.clone(),
            object_text: inferred.object_text,
            object_entity: inferred.object_entity,
            object_type_hint: object_type_hint_for_category(
                &candidate.category,
                &inferred_relation,
            ),
            object_aliases: Vec::new(),
            category: candidate.category.as_str().to_string(),
            confidence: candidate.confidence.clone(),
            source_role: candidate.source_role.clone(),
            source_ordinal: candidate.source_ordinal,
            summary,
            entity_hints,
            valid_from_ms: Some(last_message_at_ms),
            valid_to_ms: None,
            source_type: Some("conversation_session".to_string()),
            source_id: Some(session_id.to_string()),
            source_session_id: Some(session_id.to_string()),
            evidence_snippet: Some(candidate.content.clone()),
            source_metadata: json!({
                "source": "conversation_import",
                "title": title,
                "agent_id": agent_id,
            }),
        });
    }
    items
}

fn subject_type_hint_for_fact(
    title: Option<&str>,
    agent_id: Option<&str>,
    relation: &str,
    entity_hints: &[String],
) -> Option<String> {
    let Some(first_hint) = entity_hints.first() else {
        return Some("repo".to_string());
    };
    if first_hint.eq_ignore_ascii_case("repo") {
        return Some("repo".to_string());
    }
    if title
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.eq_ignore_ascii_case(first_hint))
        .unwrap_or(false)
    {
        return Some("repo".to_string());
    }
    if agent_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| format!("{value} repo"))
        .map(|value| value.eq_ignore_ascii_case(first_hint))
        .unwrap_or(false)
    {
        return Some("repo".to_string());
    }
    match normalize_relation_name(relation).as_str() {
        "decision" | "tooling_choice" | "style_preference" | "constraint" | "workflow" => {
            Some("repo".to_string())
        }
        _ => None,
    }
}

fn object_type_hint_for_category(
    category: &ConversationDurableMemoryCategory,
    relation: &str,
) -> Option<String> {
    match category {
        ConversationDurableMemoryCategory::Decision => Some("decision".to_string()),
        ConversationDurableMemoryCategory::Style => Some("preference".to_string()),
        ConversationDurableMemoryCategory::Tooling => Some("tool".to_string()),
        ConversationDurableMemoryCategory::Constraint => Some("constraint".to_string()),
        ConversationDurableMemoryCategory::Workflow => Some("workflow".to_string()),
        ConversationDurableMemoryCategory::RepoFact => {
            if normalize_relation_name(relation) == "located_in" {
                Some("file".to_string())
            } else {
                None
            }
        }
    }
}

fn relation_for_durable_category(category: &ConversationDurableMemoryCategory) -> &'static str {
    match category {
        ConversationDurableMemoryCategory::RepoFact => "repo_fact",
        ConversationDurableMemoryCategory::Decision => "decision",
        ConversationDurableMemoryCategory::Style => "style_preference",
        ConversationDurableMemoryCategory::Tooling => "tooling_choice",
        ConversationDurableMemoryCategory::Constraint => "constraint",
        ConversationDurableMemoryCategory::Workflow => "workflow",
    }
}

fn find_latest_message(
    messages: &[ConversationMessage],
    roles: &[ConversationRole],
) -> Option<String> {
    messages
        .iter()
        .rev()
        .find(|message| roles.iter().any(|role| *role == message.role))
        .and_then(|message| summarize_content(&message.content))
}

fn collect_participants(messages: &[ConversationMessage]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut participants = Vec::new();
    for message in messages {
        let label = message
            .author
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| message.role.as_str().to_string());
        if seen.insert(label.clone()) {
            participants.push(label);
        }
    }
    participants
}

fn build_summary(
    title: Option<&str>,
    latest_user_goal: Option<&str>,
    latest_assistant_reply: Option<&str>,
    open_loops: &[String],
    messages: &[ConversationMessage],
) -> String {
    let mut parts = Vec::new();
    if let Some(value) = title
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(canonical_sentence)
    {
        parts.push(format!("Session focus: {value}"));
    }
    if let Some(value) = latest_user_goal.map(canonical_sentence) {
        parts.push(format!("Recent goal: {value}"));
    }
    if let Some(value) = latest_assistant_reply.map(canonical_sentence) {
        parts.push(format!("Latest assistant context: {value}"));
    }
    if !open_loops.is_empty() {
        parts.push(format!(
            "Open loops: {}.",
            open_loops
                .iter()
                .map(|item| item.trim().trim_end_matches('.'))
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    if parts.is_empty() {
        let fallback = messages
            .iter()
            .rev()
            .filter_map(|message| summarize_content(&message.content))
            .next()
            .unwrap_or_else(|| "Conversation imported without a stable summary.".to_string());
        return canonical_sentence(&fallback);
    }
    parts.join(" ")
}

fn extract_open_loop_candidates(messages: &[ConversationMessage]) -> Vec<OpenLoopCandidate> {
    let mut seen = HashSet::new();
    let mut items = Vec::new();
    for (recency_rank, message) in messages.iter().rev().take(8).enumerate() {
        for raw_line in message.content.lines() {
            let Some((candidate, priority)) = classify_open_loop_candidate(&message.role, raw_line)
            else {
                continue;
            };
            let lowercase = candidate.to_ascii_lowercase();
            if seen.insert(lowercase) {
                items.push(OpenLoopCandidate {
                    text: canonical_sentence(&candidate),
                    priority,
                    recency_rank,
                });
            }
        }
        if items.len() >= 5 {
            break;
        }
    }
    items
}

fn classify_open_loop_candidate(role: &ConversationRole, raw_line: &str) -> Option<(String, u8)> {
    let candidate = normalize_open_loop_line(raw_line);
    if candidate.is_empty() {
        return None;
    }
    let lowercase = candidate.to_ascii_lowercase();

    for (prefix, priority) in [
        ("next step:", 0u8),
        ("todo:", 0u8),
        ("follow up:", 1u8),
        ("follow-up:", 1u8),
    ] {
        if let Some(index) = lowercase.find(prefix) {
            let normalized = capitalize_leading_ascii(&normalize_open_loop_line(
                &candidate[index + prefix.len()..],
            ));
            if !normalized.is_empty() {
                return Some((normalized, priority));
            }
        }
    }

    let is_question = matches!(role, ConversationRole::User | ConversationRole::Developer)
        && candidate.ends_with('?');
    if is_question {
        return Some((candidate, 1));
    }

    let keyword_hit = [
        ("remaining", 2u8),
        ("left to do", 2u8),
        ("still need to", 2u8),
        ("still should", 2u8),
        ("i can next", 1u8),
        ("next i can", 1u8),
    ]
    .iter()
    .find_map(|(needle, priority)| lowercase.contains(needle).then_some(*priority));
    keyword_hit.map(|priority| (candidate, priority))
}

fn select_next_step(candidates: &[OpenLoopCandidate]) -> Option<String> {
    candidates
        .iter()
        .min_by_key(|item| (item.priority, item.recency_rank))
        .map(|item| item.text.clone())
}

fn normalize_open_loop_line(raw: &str) -> String {
    let trimmed = raw
        .trim()
        .trim_start_matches(['-', '*', '+'])
        .trim()
        .trim_start_matches(|ch: char| ch.is_ascii_digit() || ch == '.' || ch == ')')
        .trim();
    collapse_whitespace(trimmed)
}

fn summarize_content(content: &str) -> Option<String> {
    let compact = collapse_whitespace(content);
    if compact.is_empty() {
        return None;
    }
    Some(canonical_sentence(&compact))
}

fn extract_durable_memory_candidates(
    messages: &[ConversationMessage],
) -> Vec<ConversationDurableMemoryCandidate> {
    let mut seen = HashSet::new();
    let mut items = Vec::new();
    for (ordinal, message) in messages.iter().enumerate() {
        for raw_line in message.content.lines() {
            let candidate = classify_repo_memory_candidate(message, ordinal, raw_line)
                .or_else(|| classify_profile_memory_candidate(message, ordinal, raw_line));
            let Some(candidate) = candidate else {
                continue;
            };
            let dedupe_key = format!(
                "{}:{}:{}",
                candidate.target.as_str(),
                candidate.category.as_str(),
                candidate.content.to_ascii_lowercase()
            );
            if seen.insert(dedupe_key) {
                items.push(candidate);
            }
            if items.len() >= 6 {
                return items;
            }
        }
    }
    items
}

fn classify_repo_memory_candidate(
    message: &ConversationMessage,
    ordinal: usize,
    raw_line: &str,
) -> Option<ConversationDurableMemoryCandidate> {
    let normalized = normalize_open_loop_line(raw_line);
    if normalized.is_empty() {
        return None;
    }
    let lowercase = normalized.to_ascii_lowercase();
    let prefixes = [
        ("decision:", ConversationDurableMemoryCategory::Decision),
        ("repo fact:", ConversationDurableMemoryCategory::RepoFact),
        ("project fact:", ConversationDurableMemoryCategory::RepoFact),
        ("architecture:", ConversationDurableMemoryCategory::RepoFact),
        (
            "implementation note:",
            ConversationDurableMemoryCategory::RepoFact,
        ),
        ("file:", ConversationDurableMemoryCategory::RepoFact),
        ("path:", ConversationDurableMemoryCategory::RepoFact),
    ];
    let (prefix, category) = prefixes
        .iter()
        .find(|(prefix, _)| lowercase.starts_with(*prefix))?;
    let content = capitalize_leading_ascii(&normalize_open_loop_line(&normalized[prefix.len()..]));
    if content.is_empty() {
        return None;
    }
    Some(ConversationDurableMemoryCandidate {
        target: ConversationDurableMemoryTarget::RepoMemory,
        category: category.clone(),
        content: canonical_sentence(&content),
        source_role: message.role.as_str().to_string(),
        source_ordinal: ordinal,
        confidence: "heuristic_explicit_v1".to_string(),
    })
}

fn classify_profile_memory_candidate(
    message: &ConversationMessage,
    ordinal: usize,
    raw_line: &str,
) -> Option<ConversationDurableMemoryCandidate> {
    if !matches!(
        message.role,
        ConversationRole::User | ConversationRole::Developer
    ) {
        return None;
    }
    let normalized = normalize_open_loop_line(raw_line);
    if normalized.is_empty() || normalized.ends_with('?') {
        return None;
    }
    let lowercase = normalized.to_ascii_lowercase();
    let category = if contains_any(
        &lowercase,
        &[
            "do not ",
            "don't ",
            "never ",
            "must not ",
            "json only",
            "strict json",
            "strictly ",
        ],
    ) {
        Some(ConversationDurableMemoryCategory::Constraint)
    } else if lowercase.starts_with("when ")
        || lowercase.starts_with("after ")
        || lowercase.starts_with("before ")
        || contains_any(
            &lowercase,
            &["commit ", "push ", "deploy ", "run tests", "keep "],
        )
    {
        Some(ConversationDurableMemoryCategory::Workflow)
    } else if contains_any(
        &lowercase,
        &[
            "style", "layout", "padding", "naming", "format", "tone", "prose", "bullet", "bullets",
            "markdown",
        ],
    ) && contains_any(
        &lowercase,
        &["prefer ", "should ", "keep ", "avoid ", "use "],
    ) {
        Some(ConversationDurableMemoryCategory::Style)
    } else if lowercase.starts_with("use ")
        || lowercase.starts_with("prefer ")
        || lowercase.starts_with("avoid ")
        || lowercase.starts_with("please use ")
        || lowercase.starts_with("we use ")
        || lowercase.starts_with("we prefer ")
        || lowercase.starts_with("must use ")
    {
        Some(ConversationDurableMemoryCategory::Tooling)
    } else {
        None
    }?;
    Some(ConversationDurableMemoryCandidate {
        target: ConversationDurableMemoryTarget::ProfileMemory,
        category,
        content: canonical_sentence(&normalized),
        source_role: message.role.as_str().to_string(),
        source_ordinal: ordinal,
        confidence: "heuristic_directive_v1".to_string(),
    })
}

fn canonical_sentence(value: &str) -> String {
    let compact = collapse_whitespace(value);
    if compact.is_empty() {
        return compact;
    }
    let mut out = compact;
    if out.len() > 180 {
        out.truncate(179);
        out.push('…');
    }
    if !out.ends_with(['.', '!', '?']) {
        out.push('.');
    }
    out
}

fn collapse_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn capitalize_leading_ascii(value: &str) -> String {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    if !first.is_ascii_lowercase() {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len());
    out.push(first.to_ascii_uppercase());
    out.extend(chars);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn message(role: ConversationRole, content: &str) -> ConversationMessage {
        ConversationMessage {
            role,
            content: content.to_string(),
            author: None,
            created_at_ms: None,
            metadata: json!({}),
        }
    }

    #[test]
    fn extracts_summary_and_open_loops_from_recent_messages() {
        let messages = vec![
            message(
                ConversationRole::User,
                "We need to add wake-up context to chat.",
            ),
            message(
                ConversationRole::Assistant,
                "I added the storage design. Next step: wire the API routes.",
            ),
            message(
                ConversationRole::User,
                "Can you also add tests for the wake-up endpoint?",
            ),
        ];

        let extracted = extract_session_artifacts(
            "session-1",
            Some("Conversation memory rollout"),
            Some("codex"),
            &messages,
            42,
        );

        assert!(extracted
            .summary
            .summary
            .contains("Conversation memory rollout"));
        assert!(extracted.summary.summary.contains("Recent goal:"));
        assert_eq!(extracted.summary.open_loops.len(), 2);
        assert_eq!(
            extracted
                .working_memory
                .as_ref()
                .and_then(|item| item.next_step.as_deref()),
            Some("Wire the API routes.")
        );
    }

    #[test]
    fn falls_back_to_recent_content_when_no_keywords_exist() {
        let messages = vec![message(
            ConversationRole::Assistant,
            "Imported historical discussion about state layout.",
        )];

        let extracted = extract_session_artifacts("session-2", None, None, &messages, 10);

        assert!(extracted
            .summary
            .summary
            .contains("Imported historical discussion"));
        assert!(extracted.summary.open_loops.is_empty());
        assert!(extracted.working_memory.is_none());
    }

    #[test]
    fn extracts_durable_memory_candidates_for_repo_and_profile_routing() {
        let messages = vec![
            message(
                ConversationRole::Developer,
                "decision: Keep wake-up routing in src/search/mod.rs",
            ),
            message(ConversationRole::User, "Use Zod for validation"),
            message(ConversationRole::User, "Do not use Moment.js here"),
            message(
                ConversationRole::User,
                "When a production fix is done, commit and deploy it",
            ),
        ];

        let extracted = extract_session_artifacts(
            "session-3",
            Some("Durable routing"),
            Some("codex"),
            &messages,
            100,
        );

        assert_eq!(extracted.durable_memories.len(), 4);
        assert_eq!(
            extracted.durable_memories[0].category,
            ConversationDurableMemoryCategory::Decision
        );
        assert_eq!(
            extracted.durable_memories[0].target,
            ConversationDurableMemoryTarget::RepoMemory
        );
        assert_eq!(
            extracted.durable_memories[1].category,
            ConversationDurableMemoryCategory::Tooling
        );
        assert_eq!(
            extracted.durable_memories[2].category,
            ConversationDurableMemoryCategory::Constraint
        );
        assert_eq!(
            extracted.durable_memories[3].category,
            ConversationDurableMemoryCategory::Workflow
        );
    }
}
