use crate::conversations::db::ConversationStore;
use crate::conversations::extract::extract_session_artifacts;
use crate::conversations::types::{
    ConversationDurableMemoryCandidate, ConversationDurableMemoryCategory,
    ConversationDurableMemoryRouteRecord, ConversationDurableMemoryStatus, ConversationImport,
    ConversationImportOptions, ImportedConversationSession,
};
use crate::knowledge::{KnowledgeFactRecord, KnowledgeGraphCandidate, KnowledgeStore};
use crate::memory::{inject_embedding_metadata, inject_repo_metadata, MemoryStore};
use crate::ollama::OllamaEmbedder;
use crate::profiles::{PreferenceCategory, ProfileEmbedder, ProfileManager};
use serde_json::json;

#[derive(Clone)]
pub struct ConversationRepoMemoryTarget {
    pub repo_id: String,
    pub store: MemoryStore,
    pub embedder: OllamaEmbedder,
    pub fallback_dim: usize,
}

#[derive(Clone)]
pub struct ConversationProfileTarget {
    pub manager: ProfileManager,
    pub embedder: Option<ProfileEmbedder>,
    pub default_role: String,
}

#[derive(Clone)]
pub struct ConversationKnowledgeTarget {
    pub store: KnowledgeStore,
    pub graph_config: crate::config::MemoryConversationGraphConfig,
}

#[derive(Clone, Default)]
pub struct ConversationRouteTargets {
    pub repo_memory: Option<ConversationRepoMemoryTarget>,
    pub profile_memory: Option<ConversationProfileTarget>,
    pub knowledge: Option<ConversationKnowledgeTarget>,
    pub default_agent_id: Option<String>,
}

pub async fn import_conversation_with_routing(
    store: ConversationStore,
    payload: ConversationImport,
    targets: ConversationRouteTargets,
) -> anyhow::Result<ImportedConversationSession> {
    import_conversation_with_routing_options(
        store,
        payload,
        ConversationImportOptions::default(),
        targets,
    )
    .await
}

pub async fn import_conversation_with_routing_options(
    store: ConversationStore,
    payload: ConversationImport,
    options: ConversationImportOptions,
    targets: ConversationRouteTargets,
) -> anyhow::Result<ImportedConversationSession> {
    let extracted_title = payload.title.clone();
    let extracted_agent_id = payload
        .agent_id
        .clone()
        .or_else(|| targets.default_agent_id.clone());
    let extracted_messages = payload.messages.clone();
    let mut imported =
        tokio::task::spawn_blocking(move || store.import_session_with_options(payload, options))
            .await??;
    if imported.deduplicated {
        return Ok(imported);
    }
    let extracted = extract_session_artifacts(
        &imported.session_id,
        extracted_title.as_deref(),
        extracted_agent_id.as_deref(),
        &extracted_messages,
        imported.summary.last_message_at_ms,
    );
    let session_id = imported.session_id.clone();
    imported.durable_memories = route_durable_memories(
        extracted.durable_memories,
        &session_id,
        imported.summary.last_message_at_ms,
        extracted_agent_id.as_deref(),
        &targets,
    )
    .await;
    imported.knowledge_facts = route_knowledge_graph_candidates(
        extracted.knowledge_graph_candidates,
        &session_id,
        imported.summary.last_message_at_ms,
        &targets,
    )
    .await;
    let extraction_lag_ms = now_epoch_ms().saturating_sub(imported.summary.last_message_at_ms);
    crate::metrics::global().record_conversation_extraction_lag(extraction_lag_ms as u128);
    Ok(imported)
}

async fn route_durable_memories(
    candidates: Vec<ConversationDurableMemoryCandidate>,
    session_id: &str,
    last_updated_ms: i64,
    route_agent_id: Option<&str>,
    targets: &ConversationRouteTargets,
) -> Vec<ConversationDurableMemoryRouteRecord> {
    let mut routed = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let record = match candidate.target.clone() {
            crate::conversations::types::ConversationDurableMemoryTarget::RepoMemory => {
                match targets.repo_memory.as_ref() {
                    Some(target) => {
                        route_repo_memory_candidate(candidate, target, session_id, last_updated_ms)
                            .await
                    }
                    None => skipped_route(candidate, "repo_memory_unavailable"),
                }
            }
            crate::conversations::types::ConversationDurableMemoryTarget::ProfileMemory => {
                match targets.profile_memory.as_ref() {
                    Some(target) => {
                        route_profile_memory_candidate(
                            candidate,
                            target,
                            route_agent_id,
                            last_updated_ms,
                        )
                        .await
                    }
                    None => skipped_route(candidate, "profile_memory_unavailable"),
                }
            }
        };
        routed.push(record);
    }
    routed
}

async fn route_knowledge_graph_candidates(
    candidates: Vec<KnowledgeGraphCandidate>,
    session_id: &str,
    last_updated_ms: i64,
    targets: &ConversationRouteTargets,
) -> Vec<KnowledgeFactRecord> {
    let Some(target) = targets.knowledge.as_ref() else {
        return Vec::new();
    };
    if candidates.is_empty() {
        return Vec::new();
    }
    let store = target.store.clone();
    let graph_config = target.graph_config.clone();
    match tokio::task::spawn_blocking({
        let candidates = candidates.clone();
        let session_id = session_id.to_string();
        move || {
            store.store_graph_candidates_with_graph_config(
                &session_id,
                last_updated_ms,
                &candidates,
                Some(&graph_config),
            )
        }
    })
    .await
    {
        Ok(Ok(facts)) => facts,
        Ok(Err(_)) | Err(_) => Vec::new(),
    }
}

fn now_epoch_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

async fn route_repo_memory_candidate(
    candidate: ConversationDurableMemoryCandidate,
    target: &ConversationRepoMemoryTarget,
    session_id: &str,
    created_at_ms: i64,
) -> ConversationDurableMemoryRouteRecord {
    let embedding = match embed_repo_memory_text(target, &candidate.content).await {
        Ok(embedding) => embedding,
        Err(reason) => return skipped_route(candidate, &reason),
    };
    let source_role = candidate.source_role.clone();
    let confidence = candidate.confidence.clone();
    let metadata = inject_embedding_metadata(
        Some(json!({
            "kind": "conversation_durable_memory",
            "category": candidate.category.as_str(),
            "source": "conversation_import",
            "conversationSessionId": session_id,
            "conversationSourceRole": source_role,
            "conversationSourceOrdinal": candidate.source_ordinal,
            "confidence": confidence,
        })),
        &embedding.provider,
        &embedding.model,
        Some(embedding.embedding.len()),
    );
    let metadata = inject_repo_metadata(metadata, &target.repo_id);
    let text = candidate.content.clone();
    let store = target.store.clone();
    match tokio::task::spawn_blocking(move || {
        store.store(&text, &embedding.embedding, metadata, created_at_ms)
    })
    .await
    {
        Ok(Ok((id, _))) => stored_route(candidate, id.to_string()),
        Ok(Err(err)) => skipped_route(candidate, &truncate_reason(&err.to_string())),
        Err(err) => skipped_route(candidate, &truncate_reason(&err.to_string())),
    }
}

async fn route_profile_memory_candidate(
    candidate: ConversationDurableMemoryCandidate,
    target: &ConversationProfileTarget,
    route_agent_id: Option<&str>,
    last_updated_ms: i64,
) -> ConversationDurableMemoryRouteRecord {
    let Some(agent_id) = route_agent_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
    else {
        return skipped_route(candidate, "missing_agent_id");
    };
    let Some(category) = profile_category_for_candidate(&candidate.category) else {
        return skipped_route(candidate, "unsupported_profile_category");
    };
    let embedding = embed_profile_memory_text(target, &candidate.content).await;
    let manager = target.manager.clone();
    let role = target.default_role.clone();
    let content = candidate.content.clone();
    match tokio::task::spawn_blocking(move || -> anyhow::Result<Option<String>> {
        if manager.get_agent(&agent_id)?.is_none() {
            manager.create_agent(&agent_id, &role, last_updated_ms)?;
        }
        let existing = manager.list_preferences(Some(&agent_id))?;
        let normalized_content = normalize_text(&content);
        let duplicate = existing.iter().any(|item| {
            item.category == category && normalize_text(&item.content) == normalized_content
        });
        if duplicate {
            return Ok(None);
        }
        let stored = manager.add_preference_with_embedding_metadata(
            &agent_id,
            &content,
            &embedding.embedding,
            category,
            last_updated_ms,
            Some(&embedding.provider),
            Some(&embedding.model),
        )?;
        Ok(Some(stored.id))
    })
    .await
    {
        Ok(Ok(Some(id))) => stored_route(candidate, id),
        Ok(Ok(None)) => skipped_route(candidate, "duplicate_preference"),
        Ok(Err(err)) => skipped_route(candidate, &truncate_reason(&err.to_string())),
        Err(err) => skipped_route(candidate, &truncate_reason(&err.to_string())),
    }
}

struct RepoEmbedding {
    embedding: Vec<f32>,
    provider: String,
    model: String,
}

async fn embed_repo_memory_text(
    target: &ConversationRepoMemoryTarget,
    text: &str,
) -> Result<RepoEmbedding, String> {
    let stored_dim = target.store.embedding_dim().ok().flatten();
    match target.embedder.embed(text).await {
        Ok(embedding) => {
            if let Some(expected) = stored_dim {
                if embedding.len() != expected {
                    if expected == 0 {
                        return Err("repo_embedding_dim_unavailable".to_string());
                    }
                    return Ok(RepoEmbedding {
                        embedding: ProfileEmbedder::fallback_embedding(text, expected),
                        provider: "fallback".to_string(),
                        model: "hash-embed-v1".to_string(),
                    });
                }
            }
            Ok(RepoEmbedding {
                embedding,
                provider: target.embedder.provider().to_string(),
                model: target.embedder.model().to_string(),
            })
        }
        Err(err) => {
            let expected =
                stored_dim.or_else(|| (target.fallback_dim > 0).then_some(target.fallback_dim));
            let Some(expected) = expected else {
                return Err(truncate_reason(&err.to_string()));
            };
            Ok(RepoEmbedding {
                embedding: ProfileEmbedder::fallback_embedding(text, expected),
                provider: "fallback".to_string(),
                model: "hash-embed-v1".to_string(),
            })
        }
    }
}

async fn embed_profile_memory_text(
    target: &ConversationProfileTarget,
    text: &str,
) -> crate::profiles::embedder::ProfileEmbedding {
    let expected = target.manager.embedding_dim().max(1);
    let Some(embedder) = target.embedder.as_ref() else {
        return crate::profiles::embedder::ProfileEmbedding {
            embedding: ProfileEmbedder::fallback_embedding(text, expected),
            provider: "fallback".to_string(),
            model: "hash-embed-v1".to_string(),
        };
    };
    match embedder.embed_with_metadata(text).await {
        Ok(embedding) if embedding.embedding.len() == expected => embedding,
        Ok(_) | Err(_) => crate::profiles::embedder::ProfileEmbedding {
            embedding: ProfileEmbedder::fallback_embedding(text, expected),
            provider: "fallback".to_string(),
            model: "hash-embed-v1".to_string(),
        },
    }
}

fn profile_category_for_candidate(
    category: &ConversationDurableMemoryCategory,
) -> Option<PreferenceCategory> {
    match category {
        ConversationDurableMemoryCategory::Style => Some(PreferenceCategory::Style),
        ConversationDurableMemoryCategory::Tooling => Some(PreferenceCategory::Tooling),
        ConversationDurableMemoryCategory::Constraint => Some(PreferenceCategory::Constraint),
        ConversationDurableMemoryCategory::Workflow => Some(PreferenceCategory::Workflow),
        ConversationDurableMemoryCategory::RepoFact
        | ConversationDurableMemoryCategory::Decision => None,
    }
}

fn stored_route(
    candidate: ConversationDurableMemoryCandidate,
    stored_id: String,
) -> ConversationDurableMemoryRouteRecord {
    ConversationDurableMemoryRouteRecord {
        target: candidate.target,
        category: candidate.category,
        status: ConversationDurableMemoryStatus::Stored,
        content: candidate.content,
        source_role: candidate.source_role,
        source_ordinal: candidate.source_ordinal,
        confidence: candidate.confidence,
        stored_id: Some(stored_id),
        reason: None,
    }
}

fn skipped_route(
    candidate: ConversationDurableMemoryCandidate,
    reason: &str,
) -> ConversationDurableMemoryRouteRecord {
    ConversationDurableMemoryRouteRecord {
        target: candidate.target,
        category: candidate.category,
        status: ConversationDurableMemoryStatus::Skipped,
        content: candidate.content,
        source_role: candidate.source_role,
        source_ordinal: candidate.source_ordinal,
        confidence: candidate.confidence,
        stored_id: None,
        reason: Some(reason.to_string()),
    }
}

fn normalize_text(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn truncate_reason(reason: &str) -> String {
    let mut out = reason.trim().to_string();
    if out.len() > 160 {
        out.truncate(160);
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversations::{ConversationMessage, ConversationRole};
    use serde_json::json;
    use std::time::Duration;
    use tempfile::tempdir;

    fn message(role: ConversationRole, content: &str) -> ConversationMessage {
        ConversationMessage {
            role,
            content: content.to_string(),
            author: None,
            created_at_ms: None,
            metadata: json!({}),
        }
    }

    #[tokio::test]
    async fn routes_repo_and_profile_memories_from_imported_conversation() -> anyhow::Result<()> {
        let repo_state = tempdir()?;
        let global_state = tempdir()?;
        let store = ConversationStore::new(repo_state.path());
        let payload = ConversationImport {
            source: "manual".to_string(),
            source_session_id: None,
            title: Some("Conversation routing".to_string()),
            agent_id: Some("codex".to_string()),
            transport: None,
            started_at_ms: Some(10),
            ended_at_ms: Some(20),
            messages: vec![
                message(
                    ConversationRole::Developer,
                    "repo fact: The wake-up endpoint lives in src/api/v1/wakeup.rs",
                ),
                message(ConversationRole::User, "Use Zod for validation"),
                message(
                    ConversationRole::User,
                    "When a production fix is done, commit and deploy it",
                ),
            ],
            metadata: json!({}),
        };
        let repo_memory = ConversationRepoMemoryTarget {
            repo_id: "repo-1".to_string(),
            store: MemoryStore::new(repo_state.path()),
            embedder: OllamaEmbedder::new(
                "http://127.0.0.1:9".to_string(),
                "fake-embed".to_string(),
                Duration::from_millis(5),
            )?,
            fallback_dim: 4,
        };
        let profile_target = ConversationProfileTarget {
            manager: ProfileManager::new(global_state.path(), 4)?,
            embedder: None,
            default_role: "conversation_import".to_string(),
        };
        let imported = import_conversation_with_routing(
            store,
            payload,
            ConversationRouteTargets {
                repo_memory: Some(repo_memory.clone()),
                profile_memory: Some(profile_target.clone()),
                knowledge: None,
                default_agent_id: Some("codex".to_string()),
            },
        )
        .await?;
        assert_eq!(imported.durable_memories.len(), 3);
        assert!(imported.durable_memories.iter().any(|item| item.status
            == ConversationDurableMemoryStatus::Stored
            && item.category == ConversationDurableMemoryCategory::RepoFact));
        let recalled = repo_memory.store.recall(
            &ProfileEmbedder::fallback_embedding("wake-up endpoint", 4),
            5,
        )?;
        assert!(!recalled.is_empty());
        let preferences = profile_target.manager.list_preferences(Some("codex"))?;
        assert_eq!(preferences.len(), 2);
        Ok(())
    }
}
