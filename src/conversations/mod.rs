pub mod db;
pub mod diary;
pub mod extract;
pub mod hooks;
pub mod import;
pub mod recall;
pub mod repo;
pub mod routing;
pub mod types;

pub use db::ConversationStore;
pub use diary::{read_diary_entries, record_diary_entry_episode, write_diary_entry};
pub use extract::{extract_session_artifacts, ExtractedConversationArtifacts};
pub use hooks::{enqueue_conversation_hook, execute_conversation_hook};
pub use import::{
    normalize_import_request, normalize_supplied_messages, ConversationImportEnvelope,
    ConversationImportFormat,
};
pub use recall::{assemble_wakeup_bundle, render_wakeup_bundle, WakeupRenderTrace};
pub use repo::*;
pub use routing::{
    import_conversation_with_routing, import_conversation_with_routing_options,
    ConversationKnowledgeTarget, ConversationProfileTarget, ConversationRepoMemoryTarget,
    ConversationRouteTargets,
};
use std::path::Path;
pub use types::{
    ConversationCaptureKind, ConversationDurableMemoryCandidate, ConversationDurableMemoryCategory,
    ConversationDurableMemoryRouteRecord, ConversationDurableMemoryStatus,
    ConversationDurableMemoryTarget, ConversationExportRecord, ConversationHookAction,
    ConversationHookEnqueueResult, ConversationHookPayload, ConversationImport,
    ConversationImportOptions, ConversationMessage, ConversationPruneResult,
    ConversationRedactResult, ConversationRetentionPolicy, ConversationRole, ConversationSearchHit,
    ConversationSearchResult, ConversationSessionList, ConversationSessionListItem,
    ConversationSessionRecord, ConversationStoredMessage, DiaryEntryRecord, DiaryReadResult,
    ImportedConversationSession, SessionSummaryRecord, TranscriptSnippet, WakeupBundle,
    WakeupTrace, WorkingMemoryRecord,
};

#[derive(Debug, Clone)]
pub struct ConversationNamespaceSweepResult {
    pub namespace_count: usize,
    pub pruned_namespace_count: usize,
    pub prune_result: ConversationPruneResult,
    pub bytes_before: u64,
    pub bytes_after: u64,
}

pub fn combined_archive_size_bytes(
    store: &ConversationStore,
    knowledge: &crate::knowledge::KnowledgeStore,
) -> u64 {
    store.archive_size_bytes() + knowledge.archive_size_bytes()
}

pub fn build_conversation_profile_target(
    manager: crate::profiles::ProfileManager,
    embedder: Option<crate::profiles::ProfileEmbedder>,
    default_role: impl Into<String>,
) -> ConversationProfileTarget {
    ConversationProfileTarget {
        manager,
        embedder,
        default_role: default_role.into(),
    }
}

pub fn build_conversation_route_targets(
    repo_memory: Option<ConversationRepoMemoryTarget>,
    profile_memory: Option<ConversationProfileTarget>,
    knowledge_store: crate::knowledge::KnowledgeStore,
    graph_config: crate::config::MemoryConversationGraphConfig,
    default_agent_id: Option<String>,
) -> ConversationRouteTargets {
    ConversationRouteTargets {
        repo_memory,
        profile_memory,
        knowledge: Some(ConversationKnowledgeTarget {
            store: knowledge_store,
            graph_config,
        }),
        default_agent_id,
    }
}

pub fn namespace_archive_size_bytes_total(base_state_dir: &Path) -> u64 {
    crate::state_layout::list_conversation_namespace_state_dirs(base_state_dir)
        .unwrap_or_default()
        .into_iter()
        .map(|dir| {
            std::fs::metadata(dir.join("conversation.db"))
                .map(|meta| meta.len())
                .unwrap_or(0)
                + std::fs::metadata(dir.join("knowledge.db"))
                    .map(|meta| meta.len())
                    .unwrap_or(0)
        })
        .sum()
}

pub fn archive_size_bytes_total(repo_total: u64, base_state_dir: Option<&Path>) -> u64 {
    repo_total
        + base_state_dir
            .map(namespace_archive_size_bytes_total)
            .unwrap_or(0)
}

pub fn sweep_conversation_namespaces(
    base_state_dir: &Path,
    policy: &ConversationRetentionPolicy,
    apply: bool,
    compact: bool,
) -> anyhow::Result<ConversationNamespaceSweepResult> {
    let namespace_dirs =
        crate::state_layout::list_conversation_namespace_state_dirs(base_state_dir)?;
    let locks_dir = crate::state_layout::StateLayout::new(base_state_dir.to_path_buf()).locks_dir();
    let mut aggregate = ConversationPruneResult::empty(apply);
    let mut pruned_namespace_count = 0usize;
    let mut bytes_before = 0u64;
    let mut bytes_after = 0u64;
    for dir in &namespace_dirs {
        let Some(state_key) = dir.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let store = ConversationStore::from_paths(
            dir.join("conversation.db"),
            locks_dir.join(format!("conversation-namespace-{state_key}.lock")),
        );
        let knowledge = crate::knowledge::KnowledgeStore::from_paths(
            dir.join("knowledge.db"),
            locks_dir.join(format!("knowledge-namespace-{state_key}.lock")),
        );
        let before = combined_archive_size_bytes(&store, &knowledge);
        let result = prune_with_knowledge(&store, &knowledge, policy, apply, compact)?;
        let after = combined_archive_size_bytes(&store, &knowledge);
        if result.has_deletions() {
            pruned_namespace_count += 1;
        }
        bytes_before += before;
        bytes_after += after;
        aggregate.absorb(result);
    }
    Ok(ConversationNamespaceSweepResult {
        namespace_count: namespace_dirs.len(),
        pruned_namespace_count,
        prune_result: aggregate,
        bytes_before,
        bytes_after,
    })
}

pub fn prune_with_knowledge(
    store: &ConversationStore,
    knowledge: &crate::knowledge::KnowledgeStore,
    policy: &ConversationRetentionPolicy,
    apply: bool,
    compact: bool,
) -> anyhow::Result<ConversationPruneResult> {
    let mut result = store.prune_retention(policy, apply)?;
    if apply && !result.deleted_session_ids.is_empty() {
        result.deleted_knowledge_facts =
            knowledge.delete_facts_for_sessions(&result.deleted_session_ids)?;
    }
    if apply && compact && result.has_deletions() {
        store.compact()?;
        knowledge.compact()?;
    }
    Ok(result)
}
