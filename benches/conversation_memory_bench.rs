use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use docdexd::config::MemoryConversationConfig;
use docdexd::conversations::{
    assemble_wakeup_bundle, extract_session_artifacts, ConversationCaptureKind, ConversationImport,
    ConversationImportOptions, ConversationMessage, ConversationRole, ConversationStore,
};
use docdexd::knowledge::KnowledgeStore;
use serde_json::json;
use tempfile::TempDir;

struct SeededArchive {
    _state_dir: TempDir,
    store: ConversationStore,
    knowledge: KnowledgeStore,
}

fn seed_archive(session_count: usize) -> SeededArchive {
    let state_dir = TempDir::new().expect("state dir");
    let store = ConversationStore::new(state_dir.path());
    let knowledge = KnowledgeStore::new(state_dir.path());

    for idx in 0..session_count {
        let created_at_ms = 1_710_000_000_000i64 + idx as i64 * 1000;
        let messages = vec![
            ConversationMessage {
                role: ConversationRole::User,
                content: format!(
                    "Repo fact: module_{idx} uses knowledge.db\nDecision: We decided to keep timeline_index_{idx} repo-scoped"
                ),
                author: None,
                created_at_ms: Some(created_at_ms),
                metadata: json!({}),
            },
            ConversationMessage {
                role: ConversationRole::Assistant,
                content: format!(
                    "Next step: keep timeline query {idx} under budget and mention alpha-token-{idx}"
                ),
                author: None,
                created_at_ms: Some(created_at_ms + 1),
                metadata: json!({}),
            },
        ];
        let imported = store
            .import_session_with_options(
                ConversationImport {
                    source: "manual".to_string(),
                    source_session_id: Some(format!("session-{idx}")),
                    title: Some(format!("Seeded session {idx}")),
                    agent_id: Some("codex".to_string()),
                    transport: Some("bench".to_string()),
                    started_at_ms: Some(created_at_ms),
                    ended_at_ms: Some(created_at_ms + 1),
                    messages: messages.clone(),
                    metadata: json!({ "seed": idx }),
                },
                ConversationImportOptions {
                    capture_kind: ConversationCaptureKind::Manual,
                    store_raw_messages: true,
                },
            )
            .expect("import session");
        let extracted = extract_session_artifacts(
            &imported.session_id,
            Some(&format!("Seeded session {idx}")),
            Some("codex"),
            &messages,
            imported.summary.last_message_at_ms,
        );
        knowledge
            .store_graph_candidates(
                &imported.session_id,
                imported.summary.last_message_at_ms,
                &extracted.knowledge_graph_candidates,
            )
            .expect("store knowledge");
    }

    SeededArchive {
        _state_dir: state_dir,
        store,
        knowledge,
    }
}

fn bench_conversation_memory(c: &mut Criterion) {
    let seeded = seed_archive(160);
    let mut group = c.benchmark_group("conversation_memory");
    group.sample_size(10);

    group.bench_function("wakeup_bundle_query", |b| {
        b.iter_batched(
            || "knowledge.db".to_string(),
            |query| {
                let bundle = assemble_wakeup_bundle(
                    &seeded.store,
                    &seeded.knowledge,
                    &MemoryConversationConfig::default(),
                    Some("codex"),
                    Some(query.as_str()),
                    6,
                    4,
                    4,
                )
                .expect("assemble wakeup");
                criterion::black_box(bundle);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("transcript_search_query", |b| {
        b.iter(|| {
            let result = seeded
                .store
                .search_sessions("alpha-token-42", Some("codex"), 10, 0)
                .expect("search sessions");
            criterion::black_box(result);
        });
    });

    group.bench_function("knowledge_query_timeline", |b| {
        b.iter(|| {
            let facts = seeded
                .knowledge
                .query_facts("knowledge.db", None, 10, 0)
                .expect("query knowledge");
            let timeline = seeded
                .knowledge
                .timeline_for_entity("knowledge.db", None, 10)
                .expect("timeline");
            criterion::black_box((facts, timeline));
        });
    });

    group.finish();
}

criterion_group!(conversation_memory_benches, bench_conversation_memory);
criterion_main!(conversation_memory_benches);
