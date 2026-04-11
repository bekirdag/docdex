use super::*;
use crate::impact::{ImpactContextAssembly, ImpactContextPruneTrace};
use crate::index::{DocumentKind, Hit};
use crate::memory::{MemoryContextItem, MemoryContextPruneTrace};
use crate::orchestrator::MemoryContextAssembly;
use crate::orchestrator::ProfileContextAssembly;
use crate::profiles::{PreferenceCategory, ProfileContextItem, ProfileContextPruneTrace};
use serde_json::json;

#[test]
fn diff_context_ordering_and_budgeting() {
    let hits = vec![Hit {
        doc_id: "doc-1".to_string(),
        rel_path: "docs/readme.md".to_string(),
        path: "docs/readme.md".to_string(),
        kind: DocumentKind::Doc,
        doc_type: None,
        score: 1.0,
        summary: "Repo summary text".to_string(),
        snippet: String::new(),
        token_estimate: 12,
        snippet_origin: None,
        snippet_truncated: None,
        line_start: None,
        line_end: None,
        score_breakdown: None,
        provenance: None,
        retrieval_explanation: None,
    }];

    let memory_context = MemoryContextAssembly {
        items: vec![MemoryContextItem {
            id: "mem-1".to_string(),
            created_at_ms: 0,
            score: 0.9,
            token_estimate: 3,
            truncated: false,
            content: "remember alpha".to_string(),
            metadata: json!({ "source": "test" }),
        }],
        prune_trace: MemoryContextPruneTrace {
            budget_tokens: 10,
            max_items: 5,
            candidates: 1,
            kept: 1,
            dropped: Vec::new(),
        },
    };

    let impact_context = ImpactContextAssembly {
        sources: vec!["src/a.rs".to_string(), "src/b.rs".to_string()],
        expanded_files: vec!["src/c.rs".to_string()],
        edges: Vec::new(),
        prune_trace: ImpactContextPruneTrace {
            requested_sources: 2,
            normalized_sources: 2,
            dropped_sources: 0,
            expanded_files: 1,
            max_edges: 10,
            max_depth: 1,
            edges: 1,
            truncated: false,
        },
    };

    let budgets = ChatContextBudgets {
        system_tokens: 0,
        wakeup_tokens: 0,
        profile_tokens: 0,
        map_tokens: 0,
        memory_tokens: 10,
        diff_tokens: 5,
        repo_tokens: 20,
        history_tokens: 0,
    };

    let (context, trace) = build_context_summary(
        "hello",
        None,
        None,
        WakeupContextTrace {
            available: 0,
            selected: 0,
            truncated: 0,
            budget_tokens: 0,
        },
        None,
        &hits,
        None,
        None,
        None,
        None,
        false,
        Some(&memory_context),
        Some(&impact_context),
        &budgets,
    );

    let memory_pos = context.find("Memory context:").expect("memory context");
    let diff_pos = context.find("Diff context:").expect("diff context");
    let repo_pos = context.find("Top local matches").expect("repo context");
    assert!(memory_pos < diff_pos);
    assert!(diff_pos < repo_pos);
    assert!(trace.diff.budget_exhausted);
    assert_eq!(trace.diff.selected, 1);
}

#[test]
fn profile_context_ordering_and_budgeting() {
    let hits = vec![Hit {
        doc_id: "doc-1".to_string(),
        rel_path: "docs/readme.md".to_string(),
        path: "docs/readme.md".to_string(),
        kind: DocumentKind::Doc,
        doc_type: None,
        score: 1.0,
        summary: "Repo summary text".to_string(),
        snippet: String::new(),
        token_estimate: 12,
        snippet_origin: None,
        snippet_truncated: None,
        line_start: None,
        line_end: None,
        score_breakdown: None,
        provenance: None,
        retrieval_explanation: None,
    }];

    let profile_context = ProfileContextAssembly {
        items: vec![
            ProfileContextItem {
                id: "pref-1".to_string(),
                agent_id: "agent-1".to_string(),
                category: PreferenceCategory::Style,
                last_updated: 0,
                score: 0.9,
                token_estimate: 3,
                truncated: false,
                content: "Keep responses concise".to_string(),
            },
            ProfileContextItem {
                id: "pref-2".to_string(),
                agent_id: "agent-1".to_string(),
                category: PreferenceCategory::Tooling,
                last_updated: 0,
                score: 0.8,
                token_estimate: 3,
                truncated: false,
                content: "Prefer ripgrep for search".to_string(),
            },
        ],
        prune_trace: ProfileContextPruneTrace {
            budget_tokens: 6,
            max_items: 5,
            candidates: 2,
            kept: 2,
            dropped: Vec::new(),
        },
    };

    let memory_context = MemoryContextAssembly {
        items: vec![MemoryContextItem {
            id: "mem-1".to_string(),
            created_at_ms: 0,
            score: 0.9,
            token_estimate: 3,
            truncated: false,
            content: "remember alpha".to_string(),
            metadata: json!({ "source": "test" }),
        }],
        prune_trace: MemoryContextPruneTrace {
            budget_tokens: 10,
            max_items: 5,
            candidates: 1,
            kept: 1,
            dropped: Vec::new(),
        },
    };

    let budgets = ChatContextBudgets {
        system_tokens: 0,
        wakeup_tokens: 0,
        profile_tokens: 3,
        map_tokens: 0,
        memory_tokens: 10,
        diff_tokens: 0,
        repo_tokens: 20,
        history_tokens: 0,
    };

    let (context, trace) = build_context_summary(
        "hello",
        None,
        None,
        WakeupContextTrace {
            available: 0,
            selected: 0,
            truncated: 0,
            budget_tokens: 0,
        },
        None,
        &hits,
        None,
        None,
        Some(&profile_context),
        None,
        false,
        Some(&memory_context),
        None,
        &budgets,
    );

    let profile_pos = context.find("Style preferences:").expect("profile context");
    let memory_pos = context.find("Memory context:").expect("memory context");
    let repo_pos = context.find("Top local matches").expect("repo context");
    assert!(profile_pos < memory_pos);
    assert!(memory_pos < repo_pos);
    assert_eq!(trace.profile.available, 1);
    assert_eq!(trace.profile.selected, 1);
}

#[test]
fn personal_preferences_context_precedes_profile_and_memory() {
    let hits = vec![Hit {
        doc_id: "doc-1".to_string(),
        rel_path: "docs/readme.md".to_string(),
        path: "docs/readme.md".to_string(),
        kind: DocumentKind::Doc,
        doc_type: None,
        score: 1.0,
        summary: "Repo summary text".to_string(),
        snippet: String::new(),
        token_estimate: 12,
        snippet_origin: None,
        snippet_truncated: None,
        line_start: None,
        line_end: None,
        score_breakdown: None,
        provenance: None,
        retrieval_explanation: None,
    }];

    let personal_preferences_context =
        crate::personal_preferences::PersonalPreferencesContextAssembly {
            items: vec![
                crate::personal_preferences::PersonalPreferencesContextItem {
                    section: "stable_preferences".to_string(),
                    content: "[coding_preference] user prefers Rust".to_string(),
                    category: "coding_preference".to_string(),
                    record_type: "preference".to_string(),
                    confidence: 0.95,
                    claim_id: None,
                    claim_origin: None,
                    truth_status: None,
                    source_repo_root: None,
                    token_estimate: 5,
                },
            ],
            trace: crate::personal_preferences::PersonalPreferencesContextTrace {
                available: 1,
                selected: 1,
                truncated: 0,
                budget_tokens: 12,
            },
        };

    let profile_context = ProfileContextAssembly {
        items: vec![ProfileContextItem {
            id: "pref-1".to_string(),
            agent_id: "agent-1".to_string(),
            category: PreferenceCategory::Style,
            last_updated: 0,
            score: 0.9,
            token_estimate: 3,
            truncated: false,
            content: "Keep responses concise".to_string(),
        }],
        prune_trace: ProfileContextPruneTrace {
            budget_tokens: 3,
            max_items: 5,
            candidates: 1,
            kept: 1,
            dropped: Vec::new(),
        },
    };

    let memory_context = MemoryContextAssembly {
        items: vec![MemoryContextItem {
            id: "mem-1".to_string(),
            created_at_ms: 0,
            score: 0.9,
            token_estimate: 3,
            truncated: false,
            content: "remember alpha".to_string(),
            metadata: json!({ "source": "test" }),
        }],
        prune_trace: MemoryContextPruneTrace {
            budget_tokens: 10,
            max_items: 5,
            candidates: 1,
            kept: 1,
            dropped: Vec::new(),
        },
    };

    let budgets = ChatContextBudgets {
        system_tokens: 0,
        wakeup_tokens: 0,
        profile_tokens: 3,
        map_tokens: 0,
        memory_tokens: 10,
        diff_tokens: 0,
        repo_tokens: 20,
        history_tokens: 0,
    };

    let (context, trace) = build_context_summary(
        "hello",
        None,
        None,
        WakeupContextTrace {
            available: 0,
            selected: 0,
            truncated: 0,
            budget_tokens: 0,
        },
        Some(&personal_preferences_context),
        &hits,
        None,
        None,
        Some(&profile_context),
        None,
        false,
        Some(&memory_context),
        None,
        &budgets,
    );

    let core_pos = context
        .find("Core memory (always-visible, advisory):")
        .expect("core memory");
    let profile_pos = context.find("Style preferences:").expect("profile context");
    let memory_pos = context.find("Memory context:").expect("memory context");
    assert!(core_pos < profile_pos);
    assert!(profile_pos < memory_pos);
    assert_eq!(trace.personal_preferences.selected, 1);
}

#[test]
fn history_budget_reuses_repo_unused_tokens() {
    let budgets = ChatContextBudgets {
        system_tokens: 0,
        wakeup_tokens: 0,
        profile_tokens: 0,
        map_tokens: 0,
        memory_tokens: 0,
        diff_tokens: 0,
        repo_tokens: 20,
        history_tokens: 0,
    };

    let (context, trace) = build_context_summary(
        "hello",
        None,
        None,
        WakeupContextTrace {
            available: 0,
            selected: 0,
            truncated: 0,
            budget_tokens: 0,
        },
        None,
        &[],
        None,
        None,
        None,
        None,
        false,
        None,
        None,
        &budgets,
    );

    assert!(trace.repo_unused_tokens > 0);
    let history = "user: one two three four five six seven eight nine ten";
    let history_budget = budgets
        .history_tokens
        .saturating_add(trace.repo_unused_tokens);
    let prompt = build_prompt("hello", &context, history, history_budget, &budgets);

    assert!(prompt.contains("Conversation history:"));
    assert!(prompt.contains("one"));
}

#[test]
fn automatic_memory_route_precedes_core_memory_sections() {
    let hits = vec![Hit {
        doc_id: "doc-1".to_string(),
        rel_path: "docs/readme.md".to_string(),
        path: "docs/readme.md".to_string(),
        kind: DocumentKind::Doc,
        doc_type: None,
        score: 1.0,
        summary: "Repo summary text".to_string(),
        snippet: String::new(),
        token_estimate: 12,
        snippet_origin: None,
        snippet_truncated: None,
        line_start: None,
        line_end: None,
        score_breakdown: None,
        provenance: None,
        retrieval_explanation: None,
    }];
    let memory_route = crate::memory_layers::MemoryRouteResponse {
        scope: crate::memory_layers::MemoryLayersScopeView {
            kind: "repo".to_string(),
            scope_id: "repo-1".to_string(),
            scope_label: "/tmp/repo".to_string(),
            repo_root: Some("/tmp/repo".to_string()),
        },
        default_agent_id: Some("codex".to_string()),
        query: "where is the auth middleware".to_string(),
        intent: "read".to_string(),
        intent_source: "explicit".to_string(),
        should_start_with_core: true,
        core_memory: vec![
            crate::memory_layers::MemoryRouteRecommendation {
                layer_id: "repo_memory".to_string(),
                title: "Repo memory".to_string(),
                score: 7,
                reason: "Repo truth first".to_string(),
                manual_tools: vec![],
                automatic_read_surfaces: vec![],
                automatic_write_surfaces: vec![],
            },
            crate::memory_layers::MemoryRouteRecommendation {
                layer_id: "profile_memory".to_string(),
                title: "Profile memory".to_string(),
                score: 2,
                reason: "Style defaults".to_string(),
                manual_tools: vec![],
                automatic_read_surfaces: vec![],
                automatic_write_surfaces: vec![],
            },
        ],
        retrievable_memory: vec![crate::memory_layers::MemoryRouteRecommendation {
            layer_id: "conversation_memory".to_string(),
            title: "Conversation memory".to_string(),
            score: 6,
            reason: "Continuity follow-up".to_string(),
            manual_tools: vec![],
            automatic_read_surfaces: vec![],
            automatic_write_surfaces: vec![],
        }],
        recommended_order: vec![
            "repo_memory".to_string(),
            "profile_memory".to_string(),
            "conversation_memory".to_string(),
        ],
        notes: vec![],
    };
    let profile_context = ProfileContextAssembly {
        items: vec![ProfileContextItem {
            id: "pref-1".to_string(),
            agent_id: "agent-1".to_string(),
            category: PreferenceCategory::Style,
            last_updated: 0,
            score: 0.9,
            token_estimate: 3,
            truncated: false,
            content: "Keep responses concise".to_string(),
        }],
        prune_trace: ProfileContextPruneTrace {
            budget_tokens: 3,
            max_items: 5,
            candidates: 1,
            kept: 1,
            dropped: Vec::new(),
        },
    };
    let memory_context = MemoryContextAssembly {
        items: vec![MemoryContextItem {
            id: "mem-1".to_string(),
            created_at_ms: 0,
            score: 0.9,
            token_estimate: 3,
            truncated: false,
            content: "remember alpha".to_string(),
            metadata: json!({ "source": "test" }),
        }],
        prune_trace: MemoryContextPruneTrace {
            budget_tokens: 10,
            max_items: 5,
            candidates: 1,
            kept: 1,
            dropped: Vec::new(),
        },
    };
    let budgets = ChatContextBudgets {
        system_tokens: 0,
        wakeup_tokens: 0,
        profile_tokens: 3,
        map_tokens: 0,
        memory_tokens: 10,
        diff_tokens: 0,
        repo_tokens: 20,
        history_tokens: 0,
    };

    let (context, _) = build_context_summary(
        "hello",
        Some(&memory_route),
        None,
        WakeupContextTrace {
            available: 0,
            selected: 0,
            truncated: 0,
            budget_tokens: 0,
        },
        None,
        &hits,
        None,
        None,
        Some(&profile_context),
        None,
        false,
        Some(&memory_context),
        None,
        &budgets,
    );

    let route_pos = context
        .find("Automatic memory route:")
        .expect("automatic memory route");
    let core_pos = context
        .find("Core memory (always-visible, advisory):")
        .expect("core memory");
    let memory_pos = context.find("Memory context:").expect("memory context");
    assert!(route_pos < core_pos);
    assert!(core_pos < memory_pos);
    assert!(context.contains("Start with core lanes: Repo memory, Profile memory."));
    assert!(context.contains("Escalate to retrievable lanes only if needed: Conversation memory."));
}

#[test]
fn wakeup_loading_requires_conversation_or_timeline_lanes() {
    let technical_route = crate::memory_layers::MemoryRouteResponse {
        scope: crate::memory_layers::MemoryLayersScopeView {
            kind: "repo".to_string(),
            scope_id: "repo-1".to_string(),
            scope_label: "/tmp/repo".to_string(),
            repo_root: Some("/tmp/repo".to_string()),
        },
        default_agent_id: None,
        query: "where is auth middleware".to_string(),
        intent: "read".to_string(),
        intent_source: "explicit".to_string(),
        should_start_with_core: true,
        core_memory: vec![],
        retrievable_memory: vec![],
        recommended_order: vec!["repo_memory".to_string(), "profile_memory".to_string()],
        notes: vec![],
    };
    let continuity_route = crate::memory_layers::MemoryRouteResponse {
        recommended_order: vec![
            "repo_memory".to_string(),
            "conversation_memory".to_string(),
            "temporal_knowledge_graph".to_string(),
        ],
        ..technical_route.clone()
    };

    assert!(!memory_route_recommends_any(
        Some(&technical_route),
        &[
            "conversation_memory",
            "diary_memory",
            "temporal_knowledge_graph",
        ],
    ));
    assert!(memory_route_recommends_any(
        Some(&continuity_route),
        &[
            "conversation_memory",
            "diary_memory",
            "temporal_knowledge_graph",
        ],
    ));
    assert!(memory_route_recommends_any(
        None,
        &[
            "conversation_memory",
            "diary_memory",
            "temporal_knowledge_graph",
        ],
    ));
}

#[test]
fn default_chat_budgets_reserve_project_map_tokens() {
    let budgets = chat_context_budgets(1024);

    assert!(budgets.wakeup_tokens > 0);
    assert!(budgets.profile_tokens > 0);
    assert!(budgets.map_tokens > 0);
    assert!(budgets.map_tokens <= PROJECT_MAP_TOKEN_CAP);
}
