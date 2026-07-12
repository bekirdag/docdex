use crate::auth::RepoOperation;

/// Authorization policy for every MCP tool advertised by `McpServer::tool_defs`.
///
/// Keep this registry exact and fail closed: encrypted-repository requests must
/// never infer privileges from a tool-name substring or silently fall back to
/// `search` when a new tool is introduced.
pub(crate) const MCP_TOOL_POLICIES: &[(&str, RepoOperation)] = &[
    ("docdex_ai_terminal_capture", RepoOperation::Admin),
    ("docdex_ai_terminal_detect", RepoOperation::Admin),
    ("docdex_ai_terminal_events", RepoOperation::Admin),
    ("docdex_ai_terminal_integrations", RepoOperation::Admin),
    (
        "docdex_ai_terminal_integrations_bootstrap",
        RepoOperation::Admin,
    ),
    ("docdex_ai_terminal_status", RepoOperation::Admin),
    ("docdex_ai_terminal_sync_skills", RepoOperation::Admin),
    ("docdex_ast", RepoOperation::Open),
    ("docdex_batch_search", RepoOperation::Search),
    ("docdex_capabilities", RepoOperation::Capabilities),
    ("docdex_clone_context", RepoOperation::Admin),
    ("docdex_clone_directive", RepoOperation::Admin),
    ("docdex_clone_evaluate", RepoOperation::Admin),
    ("docdex_clone_explain", RepoOperation::Admin),
    ("docdex_clone_replay_dataset", RepoOperation::Admin),
    ("docdex_clone_replay_evaluate", RepoOperation::Admin),
    ("docdex_clone_replay_suite", RepoOperation::Admin),
    ("docdex_conversation_delete", RepoOperation::Admin),
    ("docdex_conversation_export", RepoOperation::Admin),
    ("docdex_conversation_hook", RepoOperation::Admin),
    ("docdex_conversation_import", RepoOperation::Admin),
    ("docdex_conversation_list", RepoOperation::Admin),
    ("docdex_conversation_prune", RepoOperation::Admin),
    ("docdex_conversation_read", RepoOperation::Admin),
    ("docdex_conversation_redact", RepoOperation::Admin),
    ("docdex_conversation_search", RepoOperation::Admin),
    ("docdex_dag_export", RepoOperation::Open),
    ("docdex_diary_read", RepoOperation::Admin),
    ("docdex_diary_write", RepoOperation::Admin),
    ("docdex_files", RepoOperation::Open),
    ("docdex_get_profile", RepoOperation::Admin),
    ("docdex_impact_diagnostics", RepoOperation::Open),
    ("docdex_impact_graph", RepoOperation::Open),
    ("docdex_index", RepoOperation::Index),
    ("docdex_kg_clear", RepoOperation::Admin),
    ("docdex_kg_delete_edge", RepoOperation::Admin),
    ("docdex_kg_delete_episode", RepoOperation::Admin),
    ("docdex_kg_entity_links", RepoOperation::Admin),
    ("docdex_kg_episode", RepoOperation::Admin),
    ("docdex_kg_neighborhood", RepoOperation::Admin),
    ("docdex_kg_query", RepoOperation::Admin),
    ("docdex_kg_rebuild", RepoOperation::Admin),
    ("docdex_kg_search_edges", RepoOperation::Admin),
    ("docdex_kg_search_episodes", RepoOperation::Admin),
    ("docdex_kg_search_nodes", RepoOperation::Admin),
    ("docdex_kg_timeline", RepoOperation::Admin),
    ("docdex_llm_diagnostics", RepoOperation::AuditRead),
    ("docdex_local_completion", RepoOperation::ChatContext),
    ("docdex_memory_layers", RepoOperation::AuditRead),
    ("docdex_memory_recall", RepoOperation::Search),
    ("docdex_memory_route", RepoOperation::AuditRead),
    ("docdex_memory_save", RepoOperation::Admin),
    ("docdex_memory_store", RepoOperation::Admin),
    ("docdex_open", RepoOperation::Open),
    (
        "docdex_personal_preferences_categories",
        RepoOperation::Admin,
    ),
    (
        "docdex_personal_preferences_claim_forget",
        RepoOperation::Admin,
    ),
    (
        "docdex_personal_preferences_claim_override",
        RepoOperation::Admin,
    ),
    (
        "docdex_personal_preferences_claim_read",
        RepoOperation::Admin,
    ),
    (
        "docdex_personal_preferences_claim_review",
        RepoOperation::Admin,
    ),
    ("docdex_personal_preferences_claims", RepoOperation::Admin),
    ("docdex_personal_preferences_delete", RepoOperation::Admin),
    ("docdex_personal_preferences_export", RepoOperation::Admin),
    ("docdex_personal_preferences_feedback", RepoOperation::Admin),
    (
        "docdex_personal_preferences_generated_skill",
        RepoOperation::Admin,
    ),
    (
        "docdex_personal_preferences_generated_skill_disable",
        RepoOperation::Admin,
    ),
    (
        "docdex_personal_preferences_generated_skill_events",
        RepoOperation::Admin,
    ),
    (
        "docdex_personal_preferences_generated_skill_install",
        RepoOperation::Admin,
    ),
    (
        "docdex_personal_preferences_generated_skill_rollback",
        RepoOperation::Admin,
    ),
    (
        "docdex_personal_preferences_generated_skill_validate",
        RepoOperation::Admin,
    ),
    (
        "docdex_personal_preferences_generated_skills",
        RepoOperation::Admin,
    ),
    (
        "docdex_personal_preferences_generated_skills_autopilot",
        RepoOperation::Admin,
    ),
    (
        "docdex_personal_preferences_generated_skills_preview",
        RepoOperation::Admin,
    ),
    (
        "docdex_personal_preferences_generated_skills_render",
        RepoOperation::Admin,
    ),
    (
        "docdex_personal_preferences_generated_skills_sync",
        RepoOperation::Admin,
    ),
    ("docdex_personal_preferences_list", RepoOperation::Admin),
    ("docdex_personal_preferences_mind_map", RepoOperation::Admin),
    (
        "docdex_personal_preferences_operator_event_record",
        RepoOperation::Admin,
    ),
    (
        "docdex_personal_preferences_operator_events",
        RepoOperation::Admin,
    ),
    (
        "docdex_personal_preferences_operator_events_scan_artifacts",
        RepoOperation::Admin,
    ),
    (
        "docdex_personal_preferences_playbooks",
        RepoOperation::Admin,
    ),
    ("docdex_personal_preferences_process", RepoOperation::Admin),
    ("docdex_personal_preferences_prune", RepoOperation::Admin),
    ("docdex_personal_preferences_purge", RepoOperation::Admin),
    ("docdex_personal_preferences_read", RepoOperation::Admin),
    ("docdex_personal_preferences_redact", RepoOperation::Admin),
    (
        "docdex_personal_preferences_retention_policies",
        RepoOperation::Admin,
    ),
    ("docdex_personal_preferences_review", RepoOperation::Admin),
    ("docdex_personal_preferences_reviews", RepoOperation::Admin),
    (
        "docdex_personal_preferences_routine_explain",
        RepoOperation::Admin,
    ),
    (
        "docdex_personal_preferences_routine_read",
        RepoOperation::Admin,
    ),
    ("docdex_personal_preferences_routines", RepoOperation::Admin),
    (
        "docdex_personal_preferences_routines_rebuild",
        RepoOperation::Admin,
    ),
    ("docdex_personal_preferences_scan", RepoOperation::Admin),
    ("docdex_personal_preferences_search", RepoOperation::Admin),
    (
        "docdex_personal_preferences_snapshot_read",
        RepoOperation::Admin,
    ),
    (
        "docdex_personal_preferences_snapshots",
        RepoOperation::Admin,
    ),
    (
        "docdex_personal_preferences_snapshots_rebuild",
        RepoOperation::Admin,
    ),
    ("docdex_personal_preferences_status", RepoOperation::Admin),
    ("docdex_repo_inspect", RepoOperation::Open),
    ("docdex_rerank", RepoOperation::Search),
    ("docdex_save_preference", RepoOperation::Admin),
    ("docdex_search", RepoOperation::Search),
    ("docdex_stats", RepoOperation::Open),
    ("docdex_symbols", RepoOperation::Open),
    ("docdex_tree", RepoOperation::Open),
    ("docdex_wakeup", RepoOperation::Admin),
    ("docdex_web_research", RepoOperation::Search),
];

pub(crate) fn operation_for_tool(tool_name: &str) -> Option<RepoOperation> {
    MCP_TOOL_POLICIES
        .iter()
        .find_map(|(name, operation)| (*name == tool_name).then_some(*operation))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn policy_is_unique_and_covers_every_advertised_tool() {
        let policy_names: BTreeSet<&str> =
            MCP_TOOL_POLICIES.iter().map(|(name, _)| *name).collect();
        assert_eq!(policy_names.len(), MCP_TOOL_POLICIES.len());

        let source = include_str!("mcp_server.rs");
        let tool_defs = source
            .split_once("    fn tool_defs(&self)")
            .expect("tool_defs start")
            .1
            .split_once("    fn prompt_defs(&self)")
            .expect("tool_defs end")
            .0;
        let advertised_names: BTreeSet<&str> = tool_defs
            .lines()
            .filter_map(|line| {
                line.trim()
                    .strip_prefix("name: \"")
                    .and_then(|value| value.strip_suffix("\","))
                    .filter(|name| name.starts_with("docdex_"))
            })
            .collect();
        assert_eq!(policy_names, advertised_names);
    }

    #[test]
    fn mutators_and_sensitive_global_tools_never_fall_back_to_search() {
        for tool_name in [
            "docdex_index",
            "docdex_memory_save",
            "docdex_conversation_delete",
            "docdex_kg_clear",
            "docdex_save_preference",
            "docdex_personal_preferences_delete",
        ] {
            assert!(matches!(
                operation_for_tool(tool_name),
                Some(RepoOperation::Index | RepoOperation::Admin)
            ));
        }
        assert_eq!(
            operation_for_tool("docdex_search"),
            Some(RepoOperation::Search)
        );
        assert_eq!(operation_for_tool("docdex_unknown"), None);
    }
}
