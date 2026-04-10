use crate::config::{MemoryConversationConfig, MemoryPersonalPreferencesConfig};
use crate::conversations::ConversationStore;
use crate::knowledge::KnowledgeStore;
use crate::memory::MemoryStore;
use crate::personal_preferences::PersonalPreferencesStore;
use crate::profiles::ProfileManager;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct MemoryLayersMap {
    pub scope: MemoryLayersScopeView,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_agent_id: Option<String>,
    pub layers: Vec<MemoryLayerView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryLayersScopeView {
    pub kind: String,
    pub scope_id: String,
    pub scope_label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_root: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryLayerView {
    pub id: String,
    pub title: String,
    pub enabled: bool,
    pub scope: String,
    pub usage_priority: String,
    pub storage: MemoryLayerStorageView,
    pub agent_awareness: MemoryLayerStatusView,
    pub effective_use: MemoryLayerStatusView,
    pub manual_tools: Vec<String>,
    pub automatic_read_surfaces: Vec<String>,
    pub automatic_write_surfaces: Vec<String>,
    pub best_for: Vec<String>,
    pub avoid_for: Vec<String>,
    pub guidance: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryLayerStorageView {
    pub kind: String,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryLayerStatusView {
    pub status: String,
    pub rationale: String,
}

pub enum MemoryLayerScopeInput<'a> {
    Repo {
        repo_id: &'a str,
        repo_root: &'a Path,
    },
    Namespace {
        namespace: &'a str,
    },
}

pub struct MemoryLayersInput<'a> {
    pub scope: MemoryLayerScopeInput<'a>,
    pub default_agent_id: Option<&'a str>,
    pub repo_memory: Option<&'a MemoryStore>,
    pub profile: Option<&'a ProfileManager>,
    pub conversations: Option<&'a ConversationStore>,
    pub knowledge: Option<&'a KnowledgeStore>,
    pub conversation_config: Option<&'a MemoryConversationConfig>,
    pub personal_preferences: Option<&'a PersonalPreferencesStore>,
    pub personal_preferences_config: Option<&'a MemoryPersonalPreferencesConfig>,
}

pub fn build_memory_layers_map(input: MemoryLayersInput<'_>) -> MemoryLayersMap {
    let scope = scope_view(&input.scope);
    let repo_scope_selected = matches!(input.scope, MemoryLayerScopeInput::Repo { .. });
    let conversation_scope_selected = true;
    let diary_startup_enabled = input
        .conversation_config
        .map(|config| config.wakeup_include_recent_diary_episodes)
        .unwrap_or(false);
    let personal_preferences_context_enabled = input
        .personal_preferences_config
        .map(|config| config.context_injection_enabled)
        .unwrap_or(false);

    let mut layers = Vec::with_capacity(6);
    layers.push(memory_layer_repo_memory(&input, repo_scope_selected));
    layers.push(memory_layer_profile(&input));
    layers.push(memory_layer_conversation(
        &input,
        conversation_scope_selected,
    ));
    layers.push(memory_layer_diary(&input, diary_startup_enabled));
    layers.push(memory_layer_knowledge_graph(&input));
    layers.push(memory_layer_personal_preferences(
        &input,
        personal_preferences_context_enabled,
    ));

    MemoryLayersMap {
        scope,
        default_agent_id: input.default_agent_id.map(ToOwned::to_owned),
        layers,
    }
}

fn scope_view(scope: &MemoryLayerScopeInput<'_>) -> MemoryLayersScopeView {
    match scope {
        MemoryLayerScopeInput::Repo { repo_id, repo_root } => MemoryLayersScopeView {
            kind: "repo".to_string(),
            scope_id: (*repo_id).to_string(),
            scope_label: normalize_path(repo_root),
            repo_root: Some(normalize_path(repo_root)),
        },
        MemoryLayerScopeInput::Namespace { namespace } => MemoryLayersScopeView {
            kind: "conversation_namespace".to_string(),
            scope_id: format!("namespace:{namespace}"),
            scope_label: format!("conversation_namespace:{namespace}"),
            repo_root: None,
        },
    }
}

fn memory_layer_repo_memory(
    input: &MemoryLayersInput<'_>,
    repo_scope_selected: bool,
) -> MemoryLayerView {
    let enabled = input.repo_memory.is_some() && repo_scope_selected;
    let (awareness, effective_use, storage) = if let Some(store) = input.repo_memory {
        if repo_scope_selected {
            (
                strong_status(
                    "Agent instructions explicitly require repo memory for project facts and codebase discoveries.",
                ),
                strong_status(
                    "Direct save/recall tools and chat-context assembly make repo memory easy to use for code work.",
                ),
                storage("sqlite_vec", vec![normalize_path(store.path())]),
            )
        } else {
            (
                disabled_status(
                    "Repo memory only works with a repo scope; the current request is using a conversation namespace.",
                ),
                disabled_status(
                    "Repo-scoped technical facts are unavailable until the agent switches back to a repo scope.",
                ),
                storage("sqlite_vec", Vec::new()),
            )
        }
    } else {
        (
            disabled_status("Repo memory is disabled for this server or repo."),
            disabled_status(
                "Agents cannot save or recall repo facts until repo memory is enabled.",
            ),
            storage("sqlite_vec", Vec::new()),
        )
    };

    MemoryLayerView {
        id: "repo_memory".to_string(),
        title: "Repo Memory".to_string(),
        enabled,
        scope: "repo".to_string(),
        usage_priority: "always".to_string(),
        storage,
        agent_awareness: awareness,
        effective_use,
        manual_tools: vec![
            "docdex_memory_save".to_string(),
            "docdex_memory_recall".to_string(),
        ],
        automatic_read_surfaces: vec!["/v1/chat/completions".to_string()],
        automatic_write_surfaces: vec![
            "/v1/conversations/import (durable repo fact routing)".to_string(),
            "/v1/hooks/conversation (durable repo fact routing)".to_string(),
        ],
        best_for: vec![
            "code locations and technical facts".to_string(),
            "architecture decisions tied to this repo".to_string(),
            "project-specific gotchas and conventions".to_string(),
        ],
        avoid_for: vec![
            "global user preferences".to_string(),
            "temporary session notes better suited for diary or conversation memory".to_string(),
        ],
        guidance: "Use repo memory for durable technical truth that should stay attached to this repository."
            .to_string(),
    }
}

fn memory_layer_profile(input: &MemoryLayersInput<'_>) -> MemoryLayerView {
    let enabled = input.profile.is_some();
    let (awareness, effective_use, storage) = if let Some(profile) = input.profile {
        (
            strong_status(
                "Profile memory is called out as a mandatory lobe and does not depend on repo scoping.",
            ),
            strong_status(
                "Agents have direct get/save tools and chat can consume profile context without extra plumbing.",
            ),
            storage("sqlite", vec![normalize_path(profile.db_path())]),
        )
    } else {
        (
            disabled_status("Global profile memory is unavailable in the current server state."),
            disabled_status("Agents cannot persist or recall global preferences until profile memory is initialized."),
            storage("sqlite", Vec::new()),
        )
    };

    MemoryLayerView {
        id: "profile_memory".to_string(),
        title: "Profile Memory".to_string(),
        enabled,
        scope: "global".to_string(),
        usage_priority: "always".to_string(),
        storage,
        agent_awareness: awareness,
        effective_use,
        manual_tools: vec![
            "docdex_get_profile".to_string(),
            "docdex_save_preference".to_string(),
        ],
        automatic_read_surfaces: vec!["/v1/chat/completions".to_string()],
        automatic_write_surfaces: vec![
            "/v1/conversations/import (preference routing)".to_string(),
            "/v1/hooks/conversation (preference routing)".to_string(),
        ],
        best_for: vec![
            "user style and communication preferences".to_string(),
            "tooling constraints that apply across repos".to_string(),
            "agent-specific role and workflow defaults".to_string(),
        ],
        avoid_for: vec![
            "repo-specific code facts".to_string(),
            "large transcript archives".to_string(),
        ],
        guidance: "Use profile memory for global preferences, constraints, and agent identity that should carry across repositories."
            .to_string(),
    }
}

fn memory_layer_conversation(
    input: &MemoryLayersInput<'_>,
    _conversation_scope_selected: bool,
) -> MemoryLayerView {
    let enabled = input.conversations.is_some();
    let (awareness, effective_use, storage) = if let Some(store) = input.conversations {
        (
            strong_status(
                "The memory-layer map and MCP instructions now describe conversation memory as the archive and wake-up lane.",
            ),
            strong_status(
                "Import, search, wake-up, chat integration, and hook capture cover both manual and automatic use.",
            ),
            storage("sqlite", vec![normalize_path(store.path())]),
        )
    } else {
        (
            disabled_status("Conversation memory is disabled for the current scope."),
            disabled_status("Agents cannot inspect or reuse prior sessions until conversation memory is enabled."),
            storage("sqlite", Vec::new()),
        )
    };

    MemoryLayerView {
        id: "conversation_memory".to_string(),
        title: "Conversation Memory".to_string(),
        enabled,
        scope: "repo_or_conversation_namespace".to_string(),
        usage_priority: "when_relevant".to_string(),
        storage,
        agent_awareness: awareness,
        effective_use,
        manual_tools: vec![
            "docdex_conversation_import".to_string(),
            "docdex_conversation_search".to_string(),
            "docdex_conversation_list".to_string(),
            "docdex_conversation_read".to_string(),
            "docdex_conversation_export".to_string(),
            "docdex_conversation_redact".to_string(),
            "docdex_conversation_delete".to_string(),
            "docdex_conversation_prune".to_string(),
            "docdex_wakeup".to_string(),
        ],
        automatic_read_surfaces: vec![
            "/v1/wakeup".to_string(),
            "/v1/chat/completions".to_string(),
        ],
        automatic_write_surfaces: vec![
            "/v1/conversations/import".to_string(),
            "/v1/hooks/conversation".to_string(),
        ],
        best_for: vec![
            "session continuity".to_string(),
            "finding older discussions and decisions".to_string(),
            "bounded startup context instead of transcript replay".to_string(),
        ],
        avoid_for: vec![
            "stable cross-repo preferences better stored in profile memory".to_string(),
            "structured graph queries better handled by the temporal knowledge graph".to_string(),
        ],
        guidance: "Use conversation memory for prior-session continuity, archive inspection, and wake-up context."
            .to_string(),
    }
}

fn memory_layer_diary(
    input: &MemoryLayersInput<'_>,
    diary_startup_enabled: bool,
) -> MemoryLayerView {
    let enabled = input.conversations.is_some();
    let (awareness, effective_use, storage) = if let Some(store) = input.conversations {
        (
            strong_status(
                "The diary lane is now explicitly identified as the episodic journal and handoff store for agents.",
            ),
            strong_status(
                "Direct read/write tools plus optional startup diary recall make diary entries practical for agent handoffs.",
            ),
            storage("sqlite + knowledge projection", vec![normalize_path(store.path())]),
        )
    } else {
        (
            disabled_status("Diary storage depends on conversation memory and is disabled in the current scope."),
            disabled_status("Agents cannot journal or read diary entries until conversation memory is enabled."),
            storage("sqlite + knowledge projection", Vec::new()),
        )
    };

    let automatic_read_surfaces = if diary_startup_enabled {
        vec!["/v1/wakeup".to_string(), "/v1/chat/completions".to_string()]
    } else {
        Vec::new()
    };

    MemoryLayerView {
        id: "diary_memory".to_string(),
        title: "Diary Memory".to_string(),
        enabled,
        scope: "repo_or_conversation_namespace".to_string(),
        usage_priority: "when_relevant".to_string(),
        storage,
        agent_awareness: awareness,
        effective_use,
        manual_tools: vec![
            "docdex_diary_write".to_string(),
            "docdex_diary_read".to_string(),
        ],
        automatic_read_surfaces,
        automatic_write_surfaces: vec!["/v1/diary/write".to_string()],
        best_for: vec![
            "agent handoff notes".to_string(),
            "checkpoint summaries".to_string(),
            "why a path was chosen during a session".to_string(),
        ],
        avoid_for: vec![
            "repo-wide technical truth better stored in repo memory".to_string(),
            "global personal preferences".to_string(),
        ],
        guidance: "Use diary memory for short episodic notes that a future agent run should see as a handoff or checkpoint."
            .to_string(),
    }
}

fn memory_layer_knowledge_graph(input: &MemoryLayersInput<'_>) -> MemoryLayerView {
    let enabled = input.knowledge.is_some();
    let (awareness, effective_use, storage) = if let Some(knowledge) = input.knowledge {
        (
            strong_status(
                "The memory-layer map now frames the temporal knowledge graph as the structured timeline and relationship layer.",
            ),
            strong_status(
                "Dedicated query, timeline, neighborhood, and entity-link tools make graph retrieval usable when structured recall is needed.",
            ),
            storage("sqlite", vec![normalize_path(knowledge.path())]),
        )
    } else {
        (
            disabled_status("Temporal knowledge graph storage is unavailable in the current scope."),
            disabled_status("Agents cannot query structured conversation facts until the graph store is enabled."),
            storage("sqlite", Vec::new()),
        )
    };

    MemoryLayerView {
        id: "temporal_knowledge_graph".to_string(),
        title: "Temporal Knowledge Graph".to_string(),
        enabled,
        scope: "repo_or_conversation_namespace".to_string(),
        usage_priority: "advanced".to_string(),
        storage,
        agent_awareness: awareness,
        effective_use,
        manual_tools: vec![
            "docdex_kg_query".to_string(),
            "docdex_kg_timeline".to_string(),
            "docdex_kg_search_nodes".to_string(),
            "docdex_kg_search_edges".to_string(),
            "docdex_kg_search_episodes".to_string(),
            "docdex_kg_neighborhood".to_string(),
            "docdex_kg_entity_links".to_string(),
        ],
        automatic_read_surfaces: vec!["/v1/wakeup".to_string(), "/v1/chat/completions".to_string()],
        automatic_write_surfaces: vec![
            "/v1/conversations/import".to_string(),
            "/v1/hooks/conversation".to_string(),
            "/v1/diary/write (episode projection)".to_string(),
        ],
        best_for: vec![
            "timeline questions".to_string(),
            "entity relationships and decision provenance".to_string(),
            "structured recall beyond raw transcript search".to_string(),
        ],
        avoid_for: vec![
            "simple note taking".to_string(),
            "generic preference storage".to_string(),
        ],
        guidance: "Use the temporal knowledge graph when the task is about relationships, timelines, or entity-centric recall rather than raw messages."
            .to_string(),
    }
}

fn memory_layer_personal_preferences(
    input: &MemoryLayersInput<'_>,
    personal_preferences_context_enabled: bool,
) -> MemoryLayerView {
    let enabled = input.personal_preferences.is_some();
    let (awareness, effective_use, storage) = if let Some(store) = input.personal_preferences {
        (
            strong_status(
                "The memory-layer map and MCP instructions now call out personal preferences as a separate user-specific memory subsystem.",
            ),
            strong_status(
                "Chat context injection, capture pipelines, claims/review flows, and clone-context tools make this layer operationally useful.",
            ),
            storage("sqlite + encrypted archive", vec![normalize_path(store.db_path())]),
        )
    } else {
        (
            disabled_status("Personal preferences memory is disabled for this server."),
            disabled_status("Agents cannot search or inject durable user-specific preference records until this subsystem is enabled."),
            storage("sqlite + encrypted archive", Vec::new()),
        )
    };

    let automatic_read_surfaces = if personal_preferences_context_enabled {
        vec!["/v1/chat/completions".to_string()]
    } else {
        Vec::new()
    };

    MemoryLayerView {
        id: "personal_preferences".to_string(),
        title: "Personal Preferences".to_string(),
        enabled,
        scope: "global".to_string(),
        usage_priority: "when_relevant".to_string(),
        storage,
        agent_awareness: awareness,
        effective_use,
        manual_tools: vec![
            "docdex_personal_preferences_search".to_string(),
            "docdex_personal_preferences_claims".to_string(),
            "docdex_personal_preferences_reviews".to_string(),
            "docdex_clone_context".to_string(),
            "docdex_clone_explain".to_string(),
            "docdex_clone_evaluate".to_string(),
        ],
        automatic_read_surfaces,
        automatic_write_surfaces: vec![
            "/v1/chat/completions (capture)".to_string(),
            "/v1/conversations/import".to_string(),
            "/v1/hooks/conversation".to_string(),
            "supported client transcript scans".to_string(),
        ],
        best_for: vec![
            "durable user-specific preferences".to_string(),
            "reviewable claims distilled from conversations".to_string(),
            "clone-context or preference simulation workflows".to_string(),
        ],
        avoid_for: vec![
            "repo-specific technical facts".to_string(),
            "short-lived session notes".to_string(),
        ],
        guidance: "Use personal preferences for durable user-specific context that needs richer review, claims, and clone-context flows than basic profile memory."
            .to_string(),
    }
}

fn storage(kind: &str, paths: Vec<String>) -> MemoryLayerStorageView {
    MemoryLayerStorageView {
        kind: kind.to_string(),
        paths,
    }
}

fn strong_status(rationale: &str) -> MemoryLayerStatusView {
    status("strong", rationale)
}

fn disabled_status(rationale: &str) -> MemoryLayerStatusView {
    status("disabled", rationale)
}

fn status(kind: &str, rationale: &str) -> MemoryLayerStatusView {
    MemoryLayerStatusView {
        status: kind.to_string(),
        rationale: rationale.to_string(),
    }
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MemoryConversationConfig;
    use tempfile::TempDir;

    #[test]
    fn repo_scope_marks_repo_memory_available() {
        let temp = TempDir::new().expect("tempdir");
        let state_dir = temp.path().join("state");
        let memory_store = MemoryStore::new(&state_dir);
        let conversation_store = ConversationStore::new(&state_dir);
        let knowledge_store = KnowledgeStore::new(&state_dir);
        let config = MemoryConversationConfig::default();
        let map = build_memory_layers_map(MemoryLayersInput {
            scope: MemoryLayerScopeInput::Repo {
                repo_id: "repo-1",
                repo_root: temp.path(),
            },
            default_agent_id: Some("codex"),
            repo_memory: Some(&memory_store),
            profile: None,
            conversations: Some(&conversation_store),
            knowledge: Some(&knowledge_store),
            conversation_config: Some(&config),
            personal_preferences: None,
            personal_preferences_config: None,
        });

        assert_eq!(map.scope.kind, "repo");
        let repo_memory = map
            .layers
            .iter()
            .find(|layer| layer.id == "repo_memory")
            .expect("repo memory layer");
        assert!(repo_memory.enabled);
        assert_eq!(repo_memory.agent_awareness.status, "strong");
    }

    #[test]
    fn namespace_scope_disables_repo_memory_and_keeps_conversation_layers() {
        let temp = TempDir::new().expect("tempdir");
        let state_dir = temp.path().join("state");
        let memory_store = MemoryStore::new(&state_dir);
        let conversation_store = ConversationStore::new(&state_dir);
        let knowledge_store = KnowledgeStore::new(&state_dir);
        let config = MemoryConversationConfig::default();
        let map = build_memory_layers_map(MemoryLayersInput {
            scope: MemoryLayerScopeInput::Namespace {
                namespace: "scratch",
            },
            default_agent_id: None,
            repo_memory: Some(&memory_store),
            profile: None,
            conversations: Some(&conversation_store),
            knowledge: Some(&knowledge_store),
            conversation_config: Some(&config),
            personal_preferences: None,
            personal_preferences_config: None,
        });

        let repo_memory = map
            .layers
            .iter()
            .find(|layer| layer.id == "repo_memory")
            .expect("repo memory layer");
        assert!(!repo_memory.enabled);
        assert_eq!(repo_memory.agent_awareness.status, "disabled");

        let conversation = map
            .layers
            .iter()
            .find(|layer| layer.id == "conversation_memory")
            .expect("conversation layer");
        assert!(conversation.enabled);
    }
}
