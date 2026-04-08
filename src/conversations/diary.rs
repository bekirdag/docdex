use crate::conversations::{ConversationStore, DiaryEntryRecord, DiaryReadResult};
use crate::knowledge::{KnowledgeEpisodeRecord, KnowledgeStore};
use anyhow::Result;
use serde_json::json;
use serde_json::Value;

pub async fn write_diary_entry(
    store: ConversationStore,
    agent_id: Option<String>,
    entry_type: String,
    content: String,
    source_session_id: Option<String>,
    metadata: Value,
) -> Result<DiaryEntryRecord> {
    tokio::task::spawn_blocking(move || {
        store.write_diary_entry(
            agent_id.as_deref(),
            &entry_type,
            &content,
            source_session_id.as_deref(),
            metadata,
        )
    })
    .await?
}

pub async fn read_diary_entries(
    store: ConversationStore,
    agent_id: Option<String>,
    limit: usize,
    offset: usize,
) -> Result<DiaryReadResult> {
    tokio::task::spawn_blocking(move || {
        store.read_diary_entries(agent_id.as_deref(), limit, offset)
    })
    .await?
}

pub async fn record_diary_entry_episode(
    knowledge: KnowledgeStore,
    entry: DiaryEntryRecord,
) -> Result<Option<KnowledgeEpisodeRecord>> {
    tokio::task::spawn_blocking(move || {
        knowledge.record_episode_note(
            "diary_entry",
            &entry.entry_id,
            entry.source_session_id.as_deref(),
            &entry.content,
            json!({
                "source": "diary_write",
                "entry_type": entry.entry_type,
                "agent_id": entry.agent_id,
                "diary_metadata": entry.metadata,
            }),
            entry.created_at_ms,
        )
    })
    .await?
}
