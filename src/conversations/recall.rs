use crate::conversations::db::ConversationStore;
use crate::conversations::types::{WakeupBundle, WorkingMemoryRecord};
use crate::knowledge::{
    KnowledgeEntityLinkRecord, KnowledgeEpisodeRecord, KnowledgeFactRecord,
    KnowledgeGraphEdgeRecord, KnowledgeStore,
};
use std::collections::HashSet;

pub fn assemble_wakeup_bundle(
    store: &ConversationStore,
    knowledge: &KnowledgeStore,
    agent_id: Option<&str>,
    query: Option<&str>,
    summary_limit: usize,
    knowledge_limit: usize,
    snippet_limit: usize,
) -> Result<WakeupBundle, anyhow::Error> {
    let mut bundle = store.build_wakeup_bundle(agent_id, query, summary_limit, snippet_limit)?;
    let graph_context = if let Some(query) = query.map(str::trim).filter(|value| !value.is_empty())
    {
        Some(load_graph_context(
            knowledge,
            query,
            knowledge_limit.max(1),
        )?)
    } else {
        None
    };
    if let Some((knowledge_edges, knowledge_episodes, knowledge_entity_links, knowledge_facts)) =
        graph_context
    {
        bundle.trace.graph_edge_candidates = knowledge_edges.len();
        bundle.trace.graph_episode_candidates = knowledge_episodes.len();
        bundle.trace.graph_link_candidates = knowledge_entity_links.len();
        bundle.trace.kg_candidates = knowledge_edges.len()
            + knowledge_episodes.len()
            + knowledge_entity_links.len()
            + knowledge_facts.len();
        bundle.knowledge_edges = knowledge_edges;
        bundle.knowledge_episodes = knowledge_episodes;
        bundle.knowledge_entity_links = knowledge_entity_links;
        bundle.knowledge_facts = knowledge_facts;
    }
    Ok(bundle)
}

#[derive(Debug, Clone, Default)]
pub struct WakeupRenderTrace {
    pub available: usize,
    pub selected: usize,
    pub truncated: usize,
    pub budget_tokens: usize,
    pub available_tokens: usize,
    pub selected_tokens: usize,
    pub saved_tokens: usize,
    pub working_memory_tokens: usize,
    pub summary_tokens: usize,
    pub knowledge_tokens: usize,
    pub snippet_tokens: usize,
}

pub fn render_wakeup_bundle(
    bundle: &WakeupBundle,
    budget_tokens: usize,
) -> (String, WakeupRenderTrace) {
    if budget_tokens == 0 {
        return (
            String::new(),
            WakeupRenderTrace {
                available: available_items(bundle),
                selected: 0,
                truncated: 0,
                budget_tokens,
                available_tokens: available_tokens(bundle),
                selected_tokens: 0,
                saved_tokens: available_tokens(bundle),
                working_memory_tokens: 0,
                summary_tokens: 0,
                knowledge_tokens: 0,
                snippet_tokens: 0,
            },
        );
    }

    let mut remaining = budget_tokens;
    let mut lines = Vec::new();
    let mut selected = 0usize;
    let mut truncated = 0usize;
    let mut selected_tokens = 0usize;
    let mut working_memory_tokens = 0usize;
    let mut summary_tokens = 0usize;
    let mut knowledge_tokens = 0usize;
    let mut snippet_tokens = 0usize;

    if let Some(working_memory) = bundle.working_memory.as_ref() {
        let mut section = Vec::new();
        section.push("Wake-up context:".to_string());
        append_working_memory_lines(working_memory, &mut section);
        let outcome = push_lines(&mut lines, &section, &mut remaining, &mut truncated);
        if outcome.appended {
            selected += 1;
            selected_tokens += outcome.used_tokens;
            working_memory_tokens += outcome.used_tokens;
        }
    }

    if !bundle.episodic_summaries.is_empty() {
        let mut section = vec!["Recent conversation summaries:".to_string()];
        for item in &bundle.episodic_summaries {
            let prefix = item
                .title
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| format!("- {value}: "))
                .unwrap_or_else(|| "- ".to_string());
            section.push(format!("{prefix}{}", item.summary));
        }
        let outcome = push_lines(&mut lines, &section, &mut remaining, &mut truncated);
        selected += outcome
            .inserted_lines
            .saturating_sub(1)
            .min(bundle.episodic_summaries.len());
        selected_tokens += outcome.used_tokens;
        summary_tokens += outcome.used_tokens;
    }

    if !bundle.knowledge_edges.is_empty() {
        let mut section = vec!["Relevant knowledge graph edges:".to_string()];
        for item in &bundle.knowledge_edges {
            section.push(format!(
                "- {} {} {}",
                item.subject,
                item.relation,
                item.object_entity
                    .as_deref()
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or(&item.object_text)
            ));
        }
        let outcome = push_lines(&mut lines, &section, &mut remaining, &mut truncated);
        selected += outcome
            .inserted_lines
            .saturating_sub(1)
            .min(bundle.knowledge_edges.len());
        selected_tokens += outcome.used_tokens;
        knowledge_tokens += outcome.used_tokens;
    }

    if !bundle.knowledge_episodes.is_empty() {
        let mut section = vec!["Relevant knowledge episodes:".to_string()];
        for item in &bundle.knowledge_episodes {
            section.push(format!("- [{}] {}", item.source_type, item.summary));
        }
        let outcome = push_lines(&mut lines, &section, &mut remaining, &mut truncated);
        selected += outcome
            .inserted_lines
            .saturating_sub(1)
            .min(bundle.knowledge_episodes.len());
        selected_tokens += outcome.used_tokens;
        knowledge_tokens += outcome.used_tokens;
    }

    if !bundle.knowledge_entity_links.is_empty() {
        let mut section = vec!["Relevant knowledge code links:".to_string()];
        for item in &bundle.knowledge_entity_links {
            section.push(format!(
                "- {} -> {} ({})",
                item.entity_name, item.target, item.link_type
            ));
        }
        let outcome = push_lines(&mut lines, &section, &mut remaining, &mut truncated);
        selected += outcome
            .inserted_lines
            .saturating_sub(1)
            .min(bundle.knowledge_entity_links.len());
        selected_tokens += outcome.used_tokens;
        knowledge_tokens += outcome.used_tokens;
    }

    if !bundle.knowledge_facts.is_empty() {
        let mut section = vec!["Relevant knowledge facts:".to_string()];
        for item in &bundle.knowledge_facts {
            let label = if item.subject.eq_ignore_ascii_case("repo") {
                item.relation.clone()
            } else {
                format!("{} {}", item.subject, item.relation)
            };
            section.push(format!("- {}: {}", label.trim(), item.object_text));
        }
        let outcome = push_lines(&mut lines, &section, &mut remaining, &mut truncated);
        selected += outcome
            .inserted_lines
            .saturating_sub(1)
            .min(bundle.knowledge_facts.len());
        selected_tokens += outcome.used_tokens;
        knowledge_tokens += outcome.used_tokens;
    }

    if !bundle.transcript_snippets.is_empty() {
        let mut section = vec!["Relevant prior transcript snippets:".to_string()];
        for item in &bundle.transcript_snippets {
            section.push(format!("- [{}] {}", item.role, item.content));
        }
        let outcome = push_lines(&mut lines, &section, &mut remaining, &mut truncated);
        selected += outcome
            .inserted_lines
            .saturating_sub(1)
            .min(bundle.transcript_snippets.len());
        selected_tokens += outcome.used_tokens;
        snippet_tokens += outcome.used_tokens;
    }

    let available_tokens = available_tokens(bundle);

    (
        lines.join("\n"),
        WakeupRenderTrace {
            available: available_items(bundle),
            selected,
            truncated,
            budget_tokens,
            available_tokens,
            selected_tokens,
            saved_tokens: available_tokens.saturating_sub(selected_tokens),
            working_memory_tokens,
            summary_tokens,
            knowledge_tokens,
            snippet_tokens,
        },
    )
}

fn append_working_memory_lines(item: &WorkingMemoryRecord, lines: &mut Vec<String>) {
    let next_step_normalized = item
        .next_step
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase());
    if let Some(value) = item
        .active_objective
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        lines.push(format!("- Active objective: {value}"));
    }
    if let Some(value) = item
        .next_step
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        lines.push(format!("- Next step: {value}"));
    }
    for value in &item.open_loops {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        if next_step_normalized
            .as_deref()
            .is_some_and(|next| next == trimmed.to_ascii_lowercase())
        {
            continue;
        }
        lines.push(format!("- Open loop: {trimmed}"));
    }
}

fn push_lines(
    target: &mut Vec<String>,
    section_lines: &[String],
    remaining: &mut usize,
    truncated: &mut usize,
) -> PushLinesResult {
    let start_len = target.len();
    let mut used_tokens = 0usize;
    for line in section_lines {
        if *remaining == 0 {
            break;
        }
        let tokens = estimate_tokens(line);
        if tokens <= *remaining {
            target.push(line.clone());
            *remaining = remaining.saturating_sub(tokens);
            used_tokens = used_tokens.saturating_add(tokens);
            continue;
        }
        let (snippet, truncated_tokens) = truncate_to_tokens(line, *remaining);
        if snippet.is_empty() {
            break;
        }
        target.push(snippet);
        *remaining = remaining.saturating_sub(truncated_tokens);
        used_tokens = used_tokens.saturating_add(truncated_tokens);
        *truncated += 1;
        break;
    }
    PushLinesResult {
        appended: target.len() > start_len,
        inserted_lines: target.len().saturating_sub(start_len),
        used_tokens,
    }
}

fn available_items(bundle: &WakeupBundle) -> usize {
    usize::from(bundle.working_memory.is_some())
        + bundle.episodic_summaries.len()
        + bundle.knowledge_edges.len()
        + bundle.knowledge_episodes.len()
        + bundle.knowledge_entity_links.len()
        + bundle.knowledge_facts.len()
        + bundle.transcript_snippets.len()
}

fn available_tokens(bundle: &WakeupBundle) -> usize {
    let mut total = 0usize;
    if let Some(working_memory) = bundle.working_memory.as_ref() {
        let mut section = vec!["Wake-up context:".to_string()];
        append_working_memory_lines(working_memory, &mut section);
        total += section
            .iter()
            .map(|line| estimate_tokens(line))
            .sum::<usize>();
    }
    if !bundle.episodic_summaries.is_empty() {
        total += estimate_tokens("Recent conversation summaries:");
        total += bundle
            .episodic_summaries
            .iter()
            .map(|item| {
                let prefix = item
                    .title
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(|value| format!("- {value}: "))
                    .unwrap_or_else(|| "- ".to_string());
                estimate_tokens(&format!("{prefix}{}", item.summary))
            })
            .sum::<usize>();
    }
    if !bundle.knowledge_edges.is_empty() {
        total += estimate_tokens("Relevant knowledge graph edges:");
        total += bundle
            .knowledge_edges
            .iter()
            .map(|item| {
                estimate_tokens(&format!(
                    "- {} {} {}",
                    item.subject,
                    item.relation,
                    item.object_entity
                        .as_deref()
                        .filter(|value| !value.trim().is_empty())
                        .unwrap_or(&item.object_text)
                ))
            })
            .sum::<usize>();
    }
    if !bundle.knowledge_episodes.is_empty() {
        total += estimate_tokens("Relevant knowledge episodes:");
        total += bundle
            .knowledge_episodes
            .iter()
            .map(|item| estimate_tokens(&format!("- [{}] {}", item.source_type, item.summary)))
            .sum::<usize>();
    }
    if !bundle.knowledge_entity_links.is_empty() {
        total += estimate_tokens("Relevant knowledge code links:");
        total += bundle
            .knowledge_entity_links
            .iter()
            .map(|item| {
                estimate_tokens(&format!(
                    "- {} -> {} ({})",
                    item.entity_name, item.target, item.link_type
                ))
            })
            .sum::<usize>();
    }
    if !bundle.knowledge_facts.is_empty() {
        total += estimate_tokens("Relevant knowledge facts:");
        total += bundle
            .knowledge_facts
            .iter()
            .map(|item| {
                estimate_tokens(&format!(
                    "- {} {}: {}",
                    item.subject, item.relation, item.object_text
                ))
            })
            .sum::<usize>();
    }
    if !bundle.transcript_snippets.is_empty() {
        total += estimate_tokens("Relevant prior transcript snippets:");
        total += bundle
            .transcript_snippets
            .iter()
            .map(|item| estimate_tokens(&format!("- [{}] {}", item.role, item.content)))
            .sum::<usize>();
    }
    total
}

fn load_graph_context(
    knowledge: &KnowledgeStore,
    query: &str,
    knowledge_limit: usize,
) -> Result<
    (
        Vec<KnowledgeGraphEdgeRecord>,
        Vec<KnowledgeEpisodeRecord>,
        Vec<KnowledgeEntityLinkRecord>,
        Vec<KnowledgeFactRecord>,
    ),
    anyhow::Error,
> {
    let query = query.trim();
    if query.is_empty() {
        return Ok((Vec::new(), Vec::new(), Vec::new(), Vec::new()));
    }

    let direct_edges = knowledge
        .search_edges(query, None, knowledge_limit, 0)?
        .edges;
    let mut episodes = knowledge
        .search_episodes(query, None, knowledge_limit.min(8), 0)?
        .episodes;
    let facts = knowledge
        .query_facts(query, None, knowledge_limit.min(6), 0)?
        .facts;
    let nodes = knowledge
        .search_nodes(query, None, knowledge_limit.min(3), 0)?
        .nodes;

    let mut seen_edges = HashSet::new();
    let mut edges = Vec::new();
    for edge in direct_edges {
        if seen_edges.insert(edge.edge_id.clone()) {
            edges.push(edge);
        }
    }

    let mut seen_links = HashSet::new();
    let mut links = Vec::new();
    for node in nodes {
        let neighborhood = knowledge.neighborhood_for_entity(
            &node.canonical_name,
            None,
            knowledge_limit.min(6),
        )?;
        for edge in neighborhood.edges {
            if seen_edges.insert(edge.edge_id.clone()) {
                edges.push(edge);
            }
        }
        for link in knowledge
            .entity_links_for_entity(&node.canonical_name, None, knowledge_limit.min(4))?
            .links
        {
            if seen_links.insert(link.link_id.clone()) {
                links.push(link);
            }
        }
        if edges.len() >= knowledge_limit && links.len() >= knowledge_limit.min(4) {
            break;
        }
    }

    let episode_limit = knowledge_limit.min(8).max(1);
    let mut episode_ids = episodes
        .iter()
        .map(|item| item.episode_id.clone())
        .collect::<HashSet<_>>();
    let backfill_ids = edges
        .iter()
        .filter_map(|item| item.episode_id.as_deref())
        .chain(facts.iter().filter_map(|item| item.episode_id.as_deref()))
        .filter_map(|episode_id| {
            let trimmed = episode_id.trim();
            if trimmed.is_empty() || !episode_ids.insert(trimmed.to_string()) {
                return None;
            }
            Some(trimmed.to_string())
        })
        .collect::<Vec<_>>();
    episodes.extend(
        knowledge.episode_records(&backfill_ids, episode_limit.saturating_sub(episodes.len()))?,
    );

    edges.sort_by(|left, right| {
        right
            .updated_at_ms
            .cmp(&left.updated_at_ms)
            .then_with(|| left.edge_id.cmp(&right.edge_id))
    });
    episodes.sort_by(|left, right| {
        right
            .updated_at_ms
            .cmp(&left.updated_at_ms)
            .then_with(|| left.episode_id.cmp(&right.episode_id))
    });
    links.sort_by(|left, right| {
        right
            .updated_at_ms
            .cmp(&left.updated_at_ms)
            .then_with(|| left.link_id.cmp(&right.link_id))
    });

    edges.truncate(knowledge_limit);
    episodes.truncate(episode_limit);
    links.truncate(knowledge_limit.min(6));

    Ok((edges, episodes, links, facts))
}

#[derive(Debug, Clone, Default)]
struct PushLinesResult {
    appended: bool,
    inserted_lines: usize,
    used_tokens: usize,
}

fn truncate_to_tokens(text: &str, max_tokens: usize) -> (String, usize) {
    if max_tokens == 0 {
        return (String::new(), 0);
    }
    let mut out = String::new();
    let mut count = 0usize;
    let mut iter = text.split_whitespace().peekable();
    while let Some(token) = iter.next() {
        let next_count = count + 1;
        if next_count > max_tokens {
            break;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(token);
        count = next_count;
    }
    if iter.peek().is_some() && !out.is_empty() {
        out.push('…');
    }
    (out, count)
}

fn estimate_tokens(text: &str) -> usize {
    text.split_whitespace()
        .filter(|token| !token.is_empty())
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversations::types::{
        SessionSummaryRecord, TranscriptSnippet, WakeupBundle, WorkingMemoryRecord,
    };

    #[test]
    fn renders_wakeup_sections_in_priority_order() {
        let bundle = WakeupBundle {
            agent_id: Some("codex".to_string()),
            query: Some("wakeup".to_string()),
            working_memory: Some(WorkingMemoryRecord {
                agent_id: Some("codex".to_string()),
                active_objective: Some("Ship wake-up context".to_string()),
                next_step: Some("Wire the HTTP endpoint".to_string()),
                open_loops: vec!["Add integration coverage.".to_string()],
                source_session_id: "session-1".to_string(),
                updated_at_ms: 1,
            }),
            episodic_summaries: vec![SessionSummaryRecord {
                session_id: "session-1".to_string(),
                title: Some("Wake-up".to_string()),
                summary: "Recent goal: ship wake-up context.".to_string(),
                open_loops: vec![],
                participants: vec![],
                latest_user_goal: None,
                latest_assistant_reply: None,
                last_message_at_ms: 1,
                updated_at_ms: 1,
            }],
            knowledge_facts: Vec::new(),
            transcript_snippets: vec![TranscriptSnippet {
                session_id: "session-1".to_string(),
                message_id: "msg-1".to_string(),
                role: "user".to_string(),
                content: "Please add wake-up context.".to_string(),
                created_at_ms: 1,
            }],
            ..WakeupBundle::default()
        };

        let (rendered, trace) = render_wakeup_bundle(&bundle, 64);

        let wakeup_pos = rendered.find("Wake-up context:").expect("wake-up section");
        let summary_pos = rendered
            .find("Recent conversation summaries:")
            .expect("summary section");
        let transcript_pos = rendered
            .find("Relevant prior transcript snippets:")
            .expect("transcript section");
        assert!(wakeup_pos < summary_pos);
        assert!(summary_pos < transcript_pos);
        assert_eq!(trace.available, 3);
        assert!(trace.selected >= 2);
    }

    #[test]
    fn honors_budget_by_truncating_late_sections() {
        let bundle = WakeupBundle {
            working_memory: Some(WorkingMemoryRecord {
                agent_id: None,
                active_objective: Some("one two three four".to_string()),
                next_step: Some("five six seven eight".to_string()),
                open_loops: vec![],
                source_session_id: "session-1".to_string(),
                updated_at_ms: 1,
            }),
            ..WakeupBundle::default()
        };

        let (rendered, trace) = render_wakeup_bundle(&bundle, 5);

        assert!(rendered.contains("Wake-up context:"));
        assert!(trace.truncated >= 1);
    }
}
