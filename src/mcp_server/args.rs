use super::*;

#[derive(Deserialize)]
pub(super) struct SearchArgs {
    pub(super) query: String,
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) force_web: Option<bool>,
    #[serde(default, alias = "asyncWeb")]
    pub(super) async_web: Option<bool>,
    #[serde(default)]
    pub(super) diff: Option<diff::DiffOptions>,
    #[serde(default, alias = "dagSessionId", alias = "session_id")]
    pub(super) dag_session_id: Option<String>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
}

#[derive(Deserialize, Default)]
pub(super) struct CapabilitiesArgs {}

#[derive(Deserialize)]
pub(super) struct RerankArgs {
    pub(super) query: String,
    pub(super) candidates: Vec<crate::index::Hit>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
}

#[derive(Deserialize)]
pub(super) struct BatchSearchArgs {
    pub(super) queries: Vec<String>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) include_libs: Option<bool>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
}

#[derive(Deserialize)]
pub(super) struct WebResearchArgs {
    pub(super) query: String,
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default, alias = "webLimit")]
    pub(super) web_limit: Option<usize>,
    #[serde(default)]
    pub(super) force_web: Option<bool>,
    #[serde(default, alias = "skipLocalSearch")]
    pub(super) skip_local_search: Option<bool>,
    #[serde(default, alias = "noCache")]
    pub(super) no_cache: Option<bool>,
    #[serde(default, alias = "llmFilterLocalResults")]
    pub(super) llm_filter_local_results: Option<bool>,
    #[serde(default, alias = "repoOnly")]
    pub(super) repo_only: Option<bool>,
    #[serde(default, alias = "llmModel")]
    pub(super) llm_model: Option<String>,
    #[serde(default, alias = "llmAgent")]
    pub(super) llm_agent: Option<String>,
    #[serde(default, alias = "dagSessionId", alias = "session_id")]
    pub(super) dag_session_id: Option<String>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
}

#[derive(Deserialize)]
pub(super) struct IndexArgs {
    #[serde(default)]
    pub(super) paths: Vec<PathBuf>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
}

#[derive(Deserialize)]
pub(super) struct StatsArgs {
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
}

#[derive(Deserialize)]
pub(super) struct RepoInspectArgs {
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
}

#[derive(Deserialize)]
pub(super) struct DelegateArgs {
    pub(super) task_type: String,
    pub(super) instruction: String,
    pub(super) context: String,
    #[serde(default)]
    pub(super) agent: Option<String>,
    #[serde(default, alias = "callerAgentId")]
    pub(super) caller_agent_id: Option<String>,
    #[serde(default, alias = "callerModel")]
    pub(super) caller_model: Option<String>,
    #[serde(default, alias = "primaryCostPerMillion")]
    pub(super) primary_cost_per_million: Option<f64>,
    #[serde(default, alias = "maxTokens")]
    pub(super) max_tokens: Option<u32>,
    #[serde(default, alias = "timeoutMs")]
    pub(super) timeout_ms: Option<u64>,
    #[serde(default)]
    pub(super) mode: Option<String>,
    #[serde(default)]
    pub(super) max_context_chars: Option<usize>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
}

#[derive(Deserialize)]
pub(super) struct FilesArgs {
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) offset: Option<usize>,
}

#[derive(Deserialize)]
pub(super) struct OpenArgs {
    pub(super) path: String,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default)]
    pub(super) start_line: Option<usize>,
    #[serde(default)]
    pub(super) end_line: Option<usize>,
    #[serde(default)]
    pub(super) clamp: Option<bool>,
    #[serde(default)]
    pub(super) head: Option<usize>,
}

#[derive(Deserialize)]
pub(super) struct TreeArgs {
    #[serde(default)]
    pub(super) path: Option<String>,
    #[serde(default, alias = "maxDepth")]
    pub(super) max_depth: Option<usize>,
    #[serde(default, alias = "dirsOnly")]
    pub(super) dirs_only: Option<bool>,
    #[serde(default, alias = "includeHidden")]
    pub(super) include_hidden: Option<bool>,
    #[serde(default, alias = "extraExcludes")]
    pub(super) extra_excludes: Option<Vec<String>>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
}

#[derive(Deserialize)]
pub(super) struct SymbolsArgs {
    pub(super) path: String,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
}

#[derive(Deserialize)]
pub(super) struct AstArgs {
    pub(super) path: String,
    #[serde(default, alias = "maxNodes")]
    pub(super) max_nodes: Option<usize>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
}

#[derive(Deserialize)]
pub(super) struct ImpactDiagnosticsArgs {
    #[serde(default)]
    pub(super) file: Option<String>,
    #[serde(default, alias = "project_root")]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) offset: Option<usize>,
}

#[derive(Deserialize)]
pub(super) struct ImpactGraphArgs {
    pub(super) file: String,
    #[serde(default)]
    pub(super) max_edges: Option<usize>,
    #[serde(default)]
    pub(super) max_depth: Option<usize>,
    #[serde(default)]
    pub(super) edge_types: Option<Vec<String>>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
}

#[derive(Deserialize)]
pub(super) struct DagExportArgs {
    #[serde(default, alias = "dagSessionId", alias = "dag_session_id")]
    pub(super) session_id: Option<String>,
    #[serde(default)]
    pub(super) format: Option<String>,
    #[serde(default)]
    pub(super) max_nodes: Option<usize>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
}

#[derive(Deserialize)]
pub(super) struct MemoryStoreArgs {
    pub(super) text: String,
    #[serde(default)]
    pub(super) metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
}

#[derive(Deserialize)]
pub(super) struct MemoryRecallArgs {
    pub(super) query: String,
    #[serde(default)]
    pub(super) top_k: Option<usize>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
}

#[derive(Default, Deserialize)]
pub(super) struct MemoryLayersArgs {
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    pub(super) conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct MemoryRouteArgs {
    pub(super) query: String,
    #[serde(default)]
    pub(super) intent: Option<String>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    pub(super) conversation_namespace: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct ConversationImportMessageArgs {
    pub(super) role: String,
    pub(super) content: String,
    #[serde(default)]
    pub(super) author: Option<String>,
    #[serde(default)]
    pub(super) created_at_ms: Option<i64>,
    #[serde(default)]
    pub(super) metadata: Option<serde_json::Value>,
}

#[derive(Deserialize)]
pub(super) struct ConversationImportArgs {
    #[serde(default)]
    pub(super) source: Option<String>,
    #[serde(default)]
    pub(super) source_session_id: Option<String>,
    #[serde(default)]
    pub(super) title: Option<String>,
    #[serde(default)]
    pub(super) agent_id: Option<String>,
    #[serde(default)]
    pub(super) transport: Option<String>,
    #[serde(default)]
    pub(super) started_at_ms: Option<i64>,
    #[serde(default)]
    pub(super) ended_at_ms: Option<i64>,
    #[serde(default)]
    pub(super) format: Option<String>,
    #[serde(default)]
    pub(super) messages: Option<Vec<ConversationImportMessageArgs>>,
    #[serde(default)]
    pub(super) transcript_text: Option<String>,
    #[serde(default)]
    pub(super) metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    pub(super) conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct WakeupArgs {
    #[serde(default)]
    pub(super) agent_id: Option<String>,
    #[serde(default)]
    pub(super) query: Option<String>,
    #[serde(default)]
    pub(super) max_tokens: Option<usize>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    pub(super) conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct KgQueryArgs {
    pub(super) query: String,
    #[serde(default)]
    pub(super) relation: Option<String>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) offset: Option<usize>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    pub(super) conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct KgNodeSearchArgs {
    pub(super) query: String,
    #[serde(default)]
    pub(super) entity_type: Option<String>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) offset: Option<usize>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    pub(super) conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct KgEdgeSearchArgs {
    pub(super) query: String,
    #[serde(default)]
    pub(super) relation: Option<String>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) offset: Option<usize>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    pub(super) conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct KgTimelineArgs {
    pub(super) entity: String,
    #[serde(default)]
    pub(super) relation: Option<String>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    pub(super) conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct KgEpisodeSearchArgs {
    pub(super) query: String,
    #[serde(default)]
    pub(super) source_type: Option<String>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) offset: Option<usize>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    pub(super) conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct KgNeighborhoodArgs {
    pub(super) entity: String,
    #[serde(default)]
    pub(super) relation: Option<String>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    pub(super) conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct KgEntityLinksArgs {
    pub(super) entity: String,
    #[serde(default)]
    pub(super) link_type: Option<String>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    pub(super) conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct KgEpisodeArgs {
    #[serde(alias = "id")]
    pub(super) episode_id: String,
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    pub(super) conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct KgDeleteEdgeArgs {
    #[serde(alias = "id")]
    pub(super) edge_id: String,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    pub(super) conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct KgDeleteEpisodeArgs {
    #[serde(alias = "id")]
    pub(super) episode_id: String,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    pub(super) conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct KgMaintenanceArgs {
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    pub(super) conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct ConversationListArgs {
    #[serde(default)]
    pub(super) agent_id: Option<String>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) offset: Option<usize>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    pub(super) conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct ConversationSearchArgs {
    pub(super) query: String,
    #[serde(default)]
    pub(super) agent_id: Option<String>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) offset: Option<usize>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    pub(super) conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct ConversationReadArgs {
    pub(super) session_id: String,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    pub(super) conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct ConversationDeleteArgs {
    pub(super) session_id: String,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    pub(super) conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct ConversationExportArgs {
    pub(super) session_id: String,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    pub(super) conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct ConversationRedactArgs {
    pub(super) session_id: String,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    pub(super) conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct ConversationPruneArgs {
    #[serde(default)]
    pub(super) manual_retention_days: Option<u32>,
    #[serde(default)]
    pub(super) auto_capture_retention_days: Option<u32>,
    #[serde(default)]
    pub(super) diary_retention_days: Option<u32>,
    #[serde(default)]
    pub(super) hook_event_retention_days: Option<u32>,
    #[serde(default)]
    pub(super) working_memory_retention_days: Option<u32>,
    #[serde(default)]
    pub(super) episodic_rollup_retention_days: Option<u32>,
    #[serde(default)]
    pub(super) apply: Option<bool>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    pub(super) conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct DiaryWriteArgs {
    pub(super) content: String,
    #[serde(default)]
    pub(super) agent_id: Option<String>,
    #[serde(default)]
    pub(super) entry_type: Option<String>,
    #[serde(default)]
    pub(super) source_session_id: Option<String>,
    #[serde(default)]
    pub(super) metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    pub(super) conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct DiaryReadArgs {
    #[serde(default)]
    pub(super) agent_id: Option<String>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) offset: Option<usize>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    pub(super) conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct ConversationHookArgs {
    pub(super) action: crate::conversations::ConversationHookAction,
    #[serde(default)]
    pub(super) source: Option<String>,
    #[serde(default)]
    pub(super) source_session_id: Option<String>,
    #[serde(default)]
    pub(super) title: Option<String>,
    #[serde(default)]
    pub(super) agent_id: Option<String>,
    #[serde(default)]
    pub(super) transport: Option<String>,
    #[serde(default)]
    pub(super) started_at_ms: Option<i64>,
    #[serde(default)]
    pub(super) ended_at_ms: Option<i64>,
    #[serde(default)]
    pub(super) format: Option<String>,
    #[serde(default)]
    pub(super) messages: Option<Vec<ConversationImportMessageArgs>>,
    #[serde(default)]
    pub(super) transcript_text: Option<String>,
    #[serde(default)]
    pub(super) summary_text: Option<String>,
    #[serde(default)]
    pub(super) metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub(super) wait_for_processing: Option<bool>,
    #[serde(default)]
    pub(super) project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    pub(super) repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    pub(super) conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct ProfileSaveArgs {
    #[serde(default)]
    pub(super) agent_id: Option<String>,
    pub(super) content: String,
    pub(super) category: String,
    #[serde(default)]
    pub(super) role: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct ProfileGetArgs {
    #[serde(default)]
    pub(super) agent_id: Option<String>,
}

#[derive(Default, Deserialize)]
pub(super) struct PersonalPreferencesStatusArgs {}

#[derive(Default, Deserialize)]
pub(super) struct PersonalPreferencesCategoriesArgs {}

#[derive(Default, Deserialize)]
pub(super) struct PersonalPreferencesRetentionPoliciesArgs {}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesListArgs {
    #[serde(default)]
    pub(super) status: Option<String>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) offset: Option<usize>,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesReadArgs {
    #[serde(alias = "id")]
    pub(super) capture_id: String,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesSearchArgs {
    #[serde(alias = "q")]
    pub(super) query: String,
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) include_sensitive: Option<bool>,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesReviewQueueArgs {
    #[serde(default)]
    pub(super) status: Option<String>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) offset: Option<usize>,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesReviewArgs {
    #[serde(alias = "id")]
    pub(super) record_id: String,
    pub(super) verdict: String,
    #[serde(default)]
    pub(super) notes: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesProcessArgs {
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) retry_failed: bool,
    #[serde(default)]
    pub(super) retry_stale_processing_ms: Option<i64>,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesScanArgs {
    #[serde(default)]
    pub(super) limit: Option<usize>,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesExportArgs {
    #[serde(default)]
    pub(super) capture_id: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesDeleteArgs {
    #[serde(alias = "id")]
    pub(super) capture_id: String,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesPruneArgs {
    #[serde(default)]
    pub(super) raw_retention_days: Option<u32>,
    #[serde(default)]
    pub(super) derived_retention_days: Option<u32>,
    #[serde(default)]
    pub(super) apply: Option<bool>,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesPurgeArgs {
    #[serde(default)]
    pub(super) include_exports: Option<bool>,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesClaimsArgs {
    #[serde(default, alias = "q")]
    pub(super) query: Option<String>,
    #[serde(default)]
    pub(super) truth_status: Option<String>,
    #[serde(default)]
    pub(super) claim_origin: Option<String>,
    #[serde(default)]
    pub(super) include_sensitive: Option<bool>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) offset: Option<usize>,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesClaimReadArgs {
    #[serde(alias = "id")]
    pub(super) claim_id: String,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesClaimReviewArgs {
    #[serde(alias = "id")]
    pub(super) claim_id: String,
    pub(super) verdict: String,
    #[serde(default)]
    pub(super) notes: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesClaimOverrideArgs {
    #[serde(alias = "id")]
    pub(super) claim_id: String,
    pub(super) value: String,
    #[serde(default)]
    pub(super) notes: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesClaimForgetArgs {
    #[serde(alias = "id")]
    pub(super) claim_id: String,
    #[serde(default)]
    pub(super) notes: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesFeedbackArgs {
    pub(super) event_type: String,
    #[serde(default)]
    pub(super) claim_id: Option<String>,
    #[serde(default)]
    pub(super) capture_id: Option<String>,
    #[serde(default)]
    pub(super) category: Option<String>,
    #[serde(default)]
    pub(super) attribute: Option<String>,
    #[serde(default)]
    pub(super) value: Option<String>,
    #[serde(default)]
    pub(super) notes: Option<String>,
    #[serde(default)]
    pub(super) metadata: Option<serde_json::Value>,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesOperatorEventsArgs {
    #[serde(default, alias = "kind", alias = "event_type")]
    pub(super) event_kind: Option<String>,
    #[serde(default)]
    pub(super) action: Option<String>,
    #[serde(default)]
    pub(super) repo_root: Option<String>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) offset: Option<usize>,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesOperatorEventRecordArgs {
    #[serde(default, alias = "kind", alias = "event_type")]
    pub(super) event_kind: Option<String>,
    pub(super) action: String,
    #[serde(default)]
    pub(super) summary: Option<String>,
    #[serde(default)]
    pub(super) command_text: Option<String>,
    #[serde(default)]
    pub(super) source_session_id: Option<String>,
    #[serde(default)]
    pub(super) repo_id: Option<String>,
    #[serde(default)]
    pub(super) repo_root: Option<String>,
    #[serde(default)]
    pub(super) capture_id: Option<String>,
    #[serde(default)]
    pub(super) artifact_path: Option<String>,
    #[serde(default)]
    pub(super) occurred_at_ms: Option<i64>,
    #[serde(default)]
    pub(super) metadata: Option<serde_json::Value>,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesOperatorEventScanArgs {
    #[serde(default)]
    pub(super) repo_root: Option<String>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesSnapshotsArgs {
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) offset: Option<usize>,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesSnapshotReadArgs {
    #[serde(alias = "id")]
    pub(super) snapshot_id: String,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesRoutinesArgs {
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) offset: Option<usize>,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesRoutineReadArgs {
    #[serde(alias = "id", alias = "routine_key")]
    pub(super) routine_id: String,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesMindMapArgs {
    #[serde(default, alias = "q")]
    pub(super) query: Option<String>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) include_sensitive: Option<bool>,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesPlaybooksArgs {
    #[serde(default)]
    pub(super) min_confidence: Option<f32>,
    #[serde(default)]
    pub(super) min_support_count: Option<usize>,
    #[serde(default)]
    pub(super) include_sensitive: Option<bool>,
}

#[derive(Default, Deserialize)]
pub(super) struct AiTerminalIntegrationsArgs {}

#[derive(Default, Deserialize)]
pub(super) struct AiTerminalStatusArgs {}

#[derive(Deserialize)]
pub(super) struct AiTerminalEventsArgs {
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) offset: Option<usize>,
}

#[derive(Deserialize)]
pub(super) struct AiTerminalIntegrationsBootstrapArgs {
    #[serde(default)]
    pub(super) terminals: Vec<String>,
}

#[derive(Deserialize)]
pub(super) struct AiTerminalCaptureArgs {
    pub(super) terminal: String,
    #[serde(default)]
    pub(super) integration_id: Option<String>,
    #[serde(default)]
    pub(super) source_session_id: Option<String>,
    #[serde(default)]
    pub(super) event_kind: Option<String>,
    #[serde(default)]
    pub(super) repo_scope: Option<String>,
    pub(super) summary: String,
    #[serde(default)]
    pub(super) transcript_text: Option<String>,
    #[serde(default)]
    pub(super) agent_id: Option<String>,
    #[serde(default)]
    pub(super) metadata: Option<serde_json::Value>,
}

#[derive(Deserialize)]
pub(super) struct GeneratedSkillsSyncArgs {
    #[serde(default)]
    pub(super) min_confidence: Option<f32>,
    #[serde(default)]
    pub(super) min_support_count: Option<usize>,
    #[serde(default)]
    pub(super) include_sensitive: Option<bool>,
    #[serde(default)]
    pub(super) install: Option<bool>,
    #[serde(default)]
    pub(super) terminals: Vec<String>,
}

#[derive(Default, Deserialize)]
pub(super) struct GeneratedSkillsListArgs {}

#[derive(Deserialize)]
pub(super) struct GeneratedSkillReadArgs {
    #[serde(alias = "id", alias = "slug", alias = "name")]
    pub(super) skill_id: String,
}

#[derive(Deserialize)]
pub(super) struct GeneratedSkillActionArgs {
    #[serde(default, alias = "id", alias = "slug", alias = "name")]
    pub(super) skill_id: Option<String>,
    #[serde(default)]
    pub(super) terminals: Vec<String>,
    #[serde(default)]
    pub(super) reason: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct GeneratedSkillEventsArgs {
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) offset: Option<usize>,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesCloneArgs {
    pub(super) query: String,
    #[serde(default)]
    pub(super) agent_id: Option<String>,
    #[serde(default)]
    pub(super) mode: Option<String>,
    #[serde(default)]
    pub(super) allow_sensitive: Option<bool>,
    #[serde(default)]
    pub(super) current_repo_root: Option<String>,
    #[serde(default)]
    pub(super) max_records: Option<usize>,
    #[serde(default)]
    pub(super) budget_tokens: Option<usize>,
    #[serde(default)]
    pub(super) task_type: Option<String>,
    #[serde(default)]
    pub(super) risk_level: Option<String>,
    #[serde(default)]
    pub(super) current_files: Vec<String>,
    #[serde(default)]
    pub(super) current_plan_path: Option<String>,
    #[serde(default)]
    pub(super) enforcement_level: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesCloneReplayArgs {
    pub(super) query: String,
    #[serde(default)]
    pub(super) mode: Option<String>,
    #[serde(default)]
    pub(super) allow_sensitive: Option<bool>,
    #[serde(default)]
    pub(super) current_repo_root: Option<String>,
    #[serde(default)]
    pub(super) max_records: Option<usize>,
    #[serde(default)]
    pub(super) budget_tokens: Option<usize>,
    #[serde(default)]
    pub(super) expected_categories: Vec<String>,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesCloneReplayDatasetArgs {
    #[serde(default)]
    pub(super) ci_subset: Option<bool>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) current_repo_root: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct PersonalPreferencesCloneReplaySuiteArgs {
    #[serde(default)]
    pub(super) ci_subset: Option<bool>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) threshold: Option<f32>,
    #[serde(default)]
    pub(super) allow_sensitive: Option<bool>,
    #[serde(default)]
    pub(super) current_repo_root: Option<String>,
    #[serde(default)]
    pub(super) max_records: Option<usize>,
    #[serde(default)]
    pub(super) budget_tokens: Option<usize>,
}

#[derive(Deserialize)]
pub(super) struct ResourceReadParams {
    pub(super) uri: String,
}

#[derive(Serialize)]
pub(super) struct ResourceDefinition {
    pub(super) uri: String,
    pub(super) name: String,
    pub(super) title: String,
    pub(super) description: String,
    #[serde(rename = "mimeType")]
    pub(super) mime_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) annotations: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub(super) struct ResourceTemplate {
    pub(super) name: &'static str,
    pub(super) title: &'static str,
    pub(super) description: &'static str,
    #[serde(rename = "uriTemplate")]
    pub(super) uri_template: &'static str,
    #[serde(rename = "mimeType")]
    pub(super) mime_type: &'static str,
    pub(super) variables: &'static [&'static str],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) annotations: Option<serde_json::Value>,
}
