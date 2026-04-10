use crate::conversations::extract::extract_session_artifacts;
use crate::conversations::types::{
    ConversationCaptureKind, ConversationExportRecord, ConversationHookEnqueueResult,
    ConversationHookPayload, ConversationImport, ConversationImportOptions, ConversationMessage,
    ConversationPruneResult, ConversationRedactResult, ConversationRetentionPolicy,
    ConversationSearchHit, ConversationSearchResult, ConversationSessionList,
    ConversationSessionListItem, ConversationSessionRecord, ConversationStoredMessage,
    DiaryEntryRecord, DiaryReadResult, ImportedConversationSession, SessionSummaryRecord,
    TranscriptSnippet, WakeupBundle, WakeupTrace, WorkingMemoryRecord,
};
use anyhow::{Context, Result};
use fs4::FileExt;
use parking_lot::Mutex;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

const CONVERSATION_SCHEMA_VERSION: u32 = 3;
const REDACTION_PLACEHOLDER: &str = "[redacted]";

#[derive(Clone)]
pub struct ConversationStore {
    path: PathBuf,
    lock_path: PathBuf,
    lock: Arc<Mutex<()>>,
}

impl ConversationStore {
    pub fn new(state_dir: &Path) -> Self {
        let repo_root = crate::memory::repo_state_root_from_state_dir(state_dir);
        let _ = crate::memory::ensure_repo_state_dir(&repo_root);
        let lock_dir = crate::memory::locks_dir_from_state_dir(state_dir);
        let _ = crate::state_layout::ensure_state_dir_secure(&lock_dir);
        Self::from_paths(
            crate::conversations::conversation_path(state_dir),
            crate::conversations::conversation_lock_path(state_dir),
        )
    }

    pub fn for_namespace(base_state_dir: &Path, namespace: &str) -> Self {
        let layout = crate::state_layout::StateLayout::new(base_state_dir.to_path_buf());
        let _ = layout.ensure_global_dirs();
        Self::from_paths(
            crate::conversations::conversation_namespace_path(base_state_dir, namespace),
            crate::conversations::conversation_namespace_lock_path(base_state_dir, namespace),
        )
    }

    pub fn from_paths(path: PathBuf, lock_path: PathBuf) -> Self {
        Self {
            path,
            lock_path,
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn check_access(&self) -> Result<()> {
        let _guard = self.lock.lock();
        let _file_lock = self.lock_exclusive()?;
        let _ = self.open_connection()?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn archive_size_bytes(&self) -> u64 {
        std::fs::metadata(&self.path)
            .map(|meta| meta.len())
            .unwrap_or(0)
    }

    pub fn compact(&self) -> Result<()> {
        let _guard = self.lock.lock();
        let _file_lock = self.lock_exclusive()?;
        let conn = self.open_connection()?;
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;")?;
        Ok(())
    }

    pub fn import_session(
        &self,
        import: ConversationImport,
    ) -> Result<ImportedConversationSession> {
        self.import_session_with_options(import, ConversationImportOptions::default())
    }

    pub fn import_session_with_options(
        &self,
        import: ConversationImport,
        options: ConversationImportOptions,
    ) -> Result<ImportedConversationSession> {
        let normalized = normalize_messages(import.messages);
        let message_count = normalized.len();
        let source = import.source.trim();
        if source.is_empty() {
            anyhow::bail!("source must not be empty");
        }
        if normalized.is_empty() {
            anyhow::bail!("messages must contain at least one non-empty item");
        }
        let imported_at_ms = now_epoch_ms();
        let started_at_ms = import.started_at_ms.unwrap_or_else(|| {
            normalized
                .first()
                .and_then(|item| item.created_at_ms)
                .unwrap_or(imported_at_ms)
        });
        let ended_at_ms = import.ended_at_ms.unwrap_or_else(|| {
            normalized
                .last()
                .and_then(|item| item.created_at_ms)
                .unwrap_or(imported_at_ms)
        });
        let source_session_key = import
            .source_session_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("")
            .to_string();
        let digest = conversation_digest(source, &source_session_key, &normalized)?;

        let _guard = self.lock.lock();
        let _file_lock = self.lock_exclusive()?;
        let mut conn = self.open_connection()?;

        if let Some(existing_session_id) = conn
            .query_row(
                "SELECT id FROM conversation_sessions
                 WHERE source = ?1 AND source_session_key = ?2 AND content_digest = ?3
                 LIMIT 1",
                params![source, &source_session_key, &digest],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            let summary = load_summary(&conn, &existing_session_id)?
                .context("existing conversation import missing summary row")?;
            let working_memory = load_working_memory_for_session(&conn, &existing_session_id)?;
            let capture_kind = load_session_capture_kind(&conn, &existing_session_id)?;
            let raw_messages_stored = session_raw_messages_stored(&conn, &existing_session_id)?;
            return Ok(ImportedConversationSession {
                session_id: existing_session_id,
                deduplicated: true,
                message_count,
                capture_kind,
                raw_messages_stored,
                summary,
                working_memory,
                durable_memories: Vec::new(),
                knowledge_facts: Vec::new(),
            });
        }

        let session_id = Uuid::new_v4().to_string();
        let extracted = extract_session_artifacts(
            &session_id,
            import.title.as_deref(),
            import.agent_id.as_deref(),
            &normalized,
            ended_at_ms,
        );
        let metadata_json = serde_json::to_string(&object_or_empty(import.metadata))?;
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO conversation_sessions (
                id, source, source_session_id, source_session_key, title, agent_id, transport,
                started_at_ms, ended_at_ms, imported_at_ms, message_count, capture_kind,
                raw_messages_stored, content_digest, metadata
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                &session_id,
                source,
                nullable_trimmed(import.source_session_id.as_deref()),
                &source_session_key,
                nullable_trimmed(import.title.as_deref()),
                nullable_trimmed(import.agent_id.as_deref()),
                nullable_trimmed(import.transport.as_deref()),
                started_at_ms,
                ended_at_ms,
                imported_at_ms,
                message_count as i64,
                options.capture_kind.as_str(),
                if options.store_raw_messages { 1 } else { 0 },
                &digest,
                metadata_json
            ],
        )?;
        if options.store_raw_messages {
            for (idx, message) in normalized.iter().enumerate() {
                tx.execute(
                    "INSERT INTO conversation_messages (
                        id, session_id, ordinal, role, author, content, created_at_ms, metadata
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        Uuid::new_v4().to_string(),
                        &session_id,
                        idx as i64,
                        message.role.as_str(),
                        nullable_trimmed(message.author.as_deref()),
                        message.content.trim(),
                        message.created_at_ms.unwrap_or(ended_at_ms),
                        serde_json::to_string(&object_or_empty(message.metadata.clone()))?,
                    ],
                )?;
            }
        }
        store_summary(&tx, &extracted.summary)?;
        if let Some(working_memory) = extracted.working_memory.as_ref() {
            store_working_memory(&tx, working_memory)?;
        }
        tx.commit()?;
        Ok(ImportedConversationSession {
            session_id,
            deduplicated: false,
            message_count,
            capture_kind: options.capture_kind,
            raw_messages_stored: options.store_raw_messages,
            summary: extracted.summary,
            working_memory: extracted.working_memory,
            durable_memories: Vec::new(),
            knowledge_facts: Vec::new(),
        })
    }

    pub fn build_wakeup_bundle(
        &self,
        agent_id: Option<&str>,
        query: Option<&str>,
        summary_limit: usize,
        snippet_limit: usize,
    ) -> Result<WakeupBundle> {
        let _guard = self.lock.lock();
        let _file_lock = self.lock_shared()?;
        let conn = self.open_connection()?;
        let normalized_query = query.map(str::trim).filter(|value| !value.is_empty());
        let working_memory = load_working_memory(&conn, agent_id)?;
        let summaries = load_recent_summaries(&conn, normalized_query, summary_limit.max(1))?;
        let snippets = if let Some(query) = normalized_query {
            load_transcript_snippets(&conn, query, snippet_limit)?
        } else {
            (Vec::new(), 0, false)
        };
        let working_memory_found = working_memory.is_some();
        Ok(WakeupBundle {
            agent_id: agent_id
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
            query: normalized_query.map(ToOwned::to_owned),
            working_memory,
            episodic_summaries: summaries.0,
            knowledge_facts: Vec::new(),
            knowledge_edges: Vec::new(),
            knowledge_episodes: Vec::new(),
            knowledge_entity_links: Vec::new(),
            transcript_snippets: snippets.0,
            trace: WakeupTrace {
                working_memory_found,
                summary_candidates: summaries.1,
                kg_candidates: 0,
                graph_edge_candidates: 0,
                graph_episode_candidates: 0,
                graph_link_candidates: 0,
                snippet_candidates: snippets.1,
                startup_diary_candidates: 0,
                startup_diary_selected: 0,
            },
        })
    }

    pub fn list_sessions(
        &self,
        agent_id: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<ConversationSessionList> {
        let limit = limit.max(1);
        let agent_id = agent_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let _guard = self.lock.lock();
        let _file_lock = self.lock_shared()?;
        let conn = self.open_connection()?;
        let total = if let Some(agent_id) = agent_id.as_deref() {
            conn.query_row(
                "SELECT COUNT(*) FROM conversation_sessions WHERE agent_id = ?1",
                params![agent_id],
                |row| row.get::<_, i64>(0),
            )?
        } else {
            conn.query_row("SELECT COUNT(*) FROM conversation_sessions", [], |row| {
                row.get::<_, i64>(0)
            })?
        };
        let sessions = load_session_list(&conn, agent_id.as_deref(), limit, offset)?;
        Ok(ConversationSessionList {
            total: total.max(0) as usize,
            limit,
            offset,
            sessions,
        })
    }

    pub fn search_sessions(
        &self,
        query: &str,
        agent_id: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<ConversationSearchResult> {
        let started = Instant::now();
        let query = query.trim();
        if query.is_empty() {
            anyhow::bail!("query must not be empty");
        }
        let limit = limit.max(1);
        let agent_id = agent_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let _guard = self.lock.lock();
        let _file_lock = self.lock_shared()?;
        let conn = self.open_connection()?;
        let summary_hits = load_search_summary_hits(&conn, query, agent_id.as_deref())?;
        let message_hits = load_search_message_hits(&conn, query, agent_id.as_deref())?;
        let mut merged: HashMap<String, ConversationSearchHit> = HashMap::new();
        for hit in summary_hits.into_iter().chain(message_hits) {
            match merged.get(&hit.session_id) {
                Some(existing) if !is_better_search_hit(&hit, existing) => {}
                _ => {
                    merged.insert(hit.session_id.clone(), hit);
                }
            }
        }
        let mut hits = merged.into_values().collect::<Vec<_>>();
        hits.sort_by(compare_search_hits);
        let total = hits.len();
        let hits = hits
            .into_iter()
            .skip(offset)
            .take(limit)
            .collect::<Vec<_>>();
        crate::metrics::global()
            .record_conversation_transcript_search_latency(started.elapsed().as_millis());
        Ok(ConversationSearchResult {
            query: query.to_string(),
            total,
            limit,
            offset,
            hits,
        })
    }

    pub fn read_session(&self, session_id: &str) -> Result<Option<ConversationSessionRecord>> {
        let session_id = session_id.trim();
        if session_id.is_empty() {
            anyhow::bail!("session_id must not be empty");
        }
        let _guard = self.lock.lock();
        let _file_lock = self.lock_shared()?;
        let conn = self.open_connection()?;
        load_session_record(&conn, session_id)
    }

    pub fn export_session(&self, session_id: &str) -> Result<Option<ConversationExportRecord>> {
        let session_id = session_id.trim();
        if session_id.is_empty() {
            anyhow::bail!("session_id must not be empty");
        }
        let _guard = self.lock.lock();
        let _file_lock = self.lock_shared()?;
        let conn = self.open_connection()?;
        let Some(session) = load_session_record(&conn, session_id)? else {
            return Ok(None);
        };
        let related_diary_entries = load_diary_entries_for_session(&conn, session_id)?;
        Ok(Some(ConversationExportRecord {
            session,
            related_diary_entries,
            knowledge_facts: Vec::new(),
        }))
    }

    pub fn redact_session(&self, session_id: &str) -> Result<Option<ConversationRedactResult>> {
        let session_id = session_id.trim();
        if session_id.is_empty() {
            anyhow::bail!("session_id must not be empty");
        }
        let _guard = self.lock.lock();
        let _file_lock = self.lock_exclusive()?;
        let mut conn = self.open_connection()?;
        let Some(existing_redacted_at_ms) = conn
            .query_row(
                "SELECT redacted_at_ms FROM conversation_sessions WHERE id = ?1 LIMIT 1",
                params![session_id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?
        else {
            return Ok(None);
        };
        if existing_redacted_at_ms.is_some() {
            return Ok(Some(ConversationRedactResult {
                session_id: session_id.to_string(),
                redacted: false,
                redacted_at_ms: existing_redacted_at_ms,
            }));
        }
        let redacted_at_ms = now_epoch_ms();
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE conversation_sessions
             SET title = ?2,
                 source_session_id = NULL,
                 raw_messages_stored = 0,
                 redacted_at_ms = ?3,
                 metadata = ?4
             WHERE id = ?1",
            params![
                session_id,
                REDACTION_PLACEHOLDER,
                redacted_at_ms,
                serde_json::to_string(&json!({}))?,
            ],
        )?;
        tx.execute(
            "UPDATE conversation_messages
             SET author = NULL,
                 content = ?2,
                 metadata = ?3
             WHERE session_id = ?1",
            params![
                session_id,
                REDACTION_PLACEHOLDER,
                serde_json::to_string(&json!({}))?
            ],
        )?;
        tx.execute(
            "UPDATE conversation_summaries
             SET title = ?2,
                 summary = ?2,
                 open_loops_json = ?3,
                 open_loops_text = '',
                 participants_json = ?3,
                 latest_user_goal = NULL,
                 latest_assistant_reply = NULL,
                 updated_at_ms = ?4
             WHERE session_id = ?1",
            params![
                session_id,
                REDACTION_PLACEHOLDER,
                serde_json::to_string(&Vec::<String>::new())?,
                redacted_at_ms,
            ],
        )?;
        tx.execute(
            "DELETE FROM conversation_working_memory WHERE source_session_id = ?1",
            params![session_id],
        )?;
        tx.execute(
            "UPDATE conversation_diary_entries
             SET source_session_id = NULL
             WHERE source_session_id = ?1",
            params![session_id],
        )?;
        tx.commit()?;
        Ok(Some(ConversationRedactResult {
            session_id: session_id.to_string(),
            redacted: true,
            redacted_at_ms: Some(redacted_at_ms),
        }))
    }

    pub fn delete_session(&self, session_id: &str) -> Result<bool> {
        let session_id = session_id.trim();
        if session_id.is_empty() {
            anyhow::bail!("session_id must not be empty");
        }
        let _guard = self.lock.lock();
        let _file_lock = self.lock_exclusive()?;
        let mut conn = self.open_connection()?;
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE conversation_diary_entries
             SET source_session_id = NULL
             WHERE source_session_id = ?1",
            params![session_id],
        )?;
        let deleted = tx.execute(
            "DELETE FROM conversation_sessions WHERE id = ?1",
            params![session_id],
        )?;
        tx.commit()?;
        Ok(deleted > 0)
    }

    pub fn prune_retention(
        &self,
        policy: &ConversationRetentionPolicy,
        applied: bool,
    ) -> Result<ConversationPruneResult> {
        let _guard = self.lock.lock();
        let _file_lock = self.lock_exclusive()?;
        let mut conn = self.open_connection()?;
        let now_ms = now_epoch_ms();
        let manual_ids = session_ids_older_than(
            &conn,
            ConversationCaptureKind::Manual,
            policy.manual_retention_days,
            now_ms,
        )?;
        let auto_ids = session_ids_older_than(
            &conn,
            ConversationCaptureKind::Auto,
            policy.auto_capture_retention_days,
            now_ms,
        )?;
        let deleted_diary_entries =
            count_diary_entries_older_than(&conn, policy.diary_retention_days, now_ms)?;
        let deleted_hook_events =
            count_hook_events_older_than(&conn, policy.hook_event_retention_days, now_ms)?;
        let deleted_session_ids = manual_ids
            .iter()
            .chain(auto_ids.iter())
            .cloned()
            .collect::<Vec<_>>();
        let deleted_working_memory_agent_keys = working_memory_agent_keys_for_cleanup(
            &conn,
            &deleted_session_ids,
            policy.working_memory_retention_days,
            now_ms,
        )?;
        let deleted_rollups =
            count_rollups_older_than(&conn, policy.episodic_rollup_retention_days, now_ms)?;
        let rollups = build_rollup_records(
            load_rollup_source_sessions(&conn, &deleted_session_ids)?,
            now_ms,
        )?;

        if applied {
            let tx = conn.transaction()?;
            store_rollups(&tx, &rollups)?;
            delete_working_memory_records(&tx, &deleted_working_memory_agent_keys)?;
            detach_diary_entries_for_sessions(&tx, &manual_ids)?;
            detach_diary_entries_for_sessions(&tx, &auto_ids)?;
            for session_id in manual_ids.iter().chain(auto_ids.iter()) {
                tx.execute(
                    "DELETE FROM conversation_sessions WHERE id = ?1",
                    params![session_id],
                )?;
            }
            delete_diary_entries_older_than(&tx, policy.diary_retention_days, now_ms)?;
            delete_hook_events_older_than(&tx, policy.hook_event_retention_days, now_ms)?;
            delete_rollups_older_than(&tx, policy.episodic_rollup_retention_days, now_ms)?;
            tx.commit()?;
        }

        Ok(ConversationPruneResult {
            applied,
            deleted_manual_sessions: manual_ids.len(),
            deleted_auto_sessions: auto_ids.len(),
            deleted_diary_entries,
            deleted_hook_events,
            deleted_working_memory_records: deleted_working_memory_agent_keys.len(),
            deleted_rollups,
            created_rollups: rollups.len(),
            deleted_knowledge_facts: 0,
            deleted_session_ids,
        })
    }

    pub fn write_diary_entry(
        &self,
        agent_id: Option<&str>,
        entry_type: &str,
        content: &str,
        source_session_id: Option<&str>,
        metadata: Value,
    ) -> Result<DiaryEntryRecord> {
        let entry_type = entry_type.trim();
        let content = content.trim();
        if entry_type.is_empty() {
            anyhow::bail!("entry_type must not be empty");
        }
        if content.is_empty() {
            anyhow::bail!("content must not be empty");
        }
        let created_at_ms = now_epoch_ms();
        let entry = DiaryEntryRecord {
            entry_id: Uuid::new_v4().to_string(),
            agent_id: nullable_trimmed(agent_id),
            entry_type: entry_type.to_string(),
            content: content.to_string(),
            source_session_id: nullable_trimmed(source_session_id),
            created_at_ms,
            metadata: object_or_empty(metadata),
        };
        let agent_key = normalized_agent_key(entry.agent_id.as_deref());
        let _guard = self.lock.lock();
        let _file_lock = self.lock_exclusive()?;
        let conn = self.open_connection()?;
        conn.execute(
            "INSERT INTO conversation_diary_entries (
                id, agent_key, agent_id, entry_type, content, source_session_id, created_at_ms, metadata
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                &entry.entry_id,
                agent_key,
                nullable_trimmed(entry.agent_id.as_deref()),
                &entry.entry_type,
                &entry.content,
                nullable_trimmed(entry.source_session_id.as_deref()),
                entry.created_at_ms,
                serde_json::to_string(&entry.metadata)?,
            ],
        )?;
        Ok(entry)
    }

    pub fn read_diary_entries(
        &self,
        agent_id: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<DiaryReadResult> {
        let limit = limit.max(1);
        let agent_id = nullable_trimmed(agent_id);
        let _guard = self.lock.lock();
        let _file_lock = self.lock_shared()?;
        let conn = self.open_connection()?;
        let total = if let Some(agent_key) = agent_id.as_deref() {
            conn.query_row(
                "SELECT COUNT(*) FROM conversation_diary_entries WHERE agent_key = ?1",
                params![agent_key],
                |row| row.get::<_, i64>(0),
            )?
        } else {
            conn.query_row(
                "SELECT COUNT(*) FROM conversation_diary_entries",
                [],
                |row| row.get::<_, i64>(0),
            )?
        };
        let entries = load_diary_entries(&conn, agent_id.as_deref(), limit, offset)?;
        Ok(DiaryReadResult {
            total: total.max(0) as usize,
            limit,
            offset,
            entries,
        })
    }

    pub fn enqueue_hook_event(
        &self,
        payload: &ConversationHookPayload,
    ) -> Result<ConversationHookEnqueueResult> {
        let queued_at_ms = now_epoch_ms();
        let event_id = Uuid::new_v4().to_string();
        let action = payload.action.clone();
        let metadata = object_or_empty(payload.metadata.clone());
        let payload_json = serde_json::to_string(&ConversationHookPayload {
            metadata: metadata.clone(),
            ..payload.clone()
        })?;
        let _guard = self.lock.lock();
        let _file_lock = self.lock_exclusive()?;
        let conn = self.open_connection()?;
        conn.execute(
            "INSERT INTO conversation_hook_events (
                id, action, status, source, source_session_id, agent_key, agent_id,
                queued_at_ms, processed_at_ms, payload_json, result_json, error
            ) VALUES (?1, ?2, 'queued', ?3, ?4, ?5, ?6, ?7, NULL, ?8, NULL, NULL)",
            params![
                &event_id,
                action.as_str(),
                nullable_trimmed(payload.source.as_deref()),
                nullable_trimmed(payload.source_session_id.as_deref()),
                normalized_agent_key(payload.agent_id.as_deref()),
                nullable_trimmed(payload.agent_id.as_deref()),
                queued_at_ms,
                payload_json,
            ],
        )?;
        Ok(ConversationHookEnqueueResult {
            event_id,
            action,
            status: "queued".to_string(),
            queued_at_ms,
            processed_at_ms: None,
            session_id: None,
            deduplicated: None,
            summary: None,
            working_memory: None,
            diary_entry: None,
            durable_memories: Vec::new(),
            knowledge_facts: Vec::new(),
            error: None,
        })
    }

    pub fn mark_hook_event_processed(
        &self,
        event_id: &str,
        result: &ConversationHookEnqueueResult,
    ) -> Result<()> {
        let _guard = self.lock.lock();
        let _file_lock = self.lock_exclusive()?;
        let conn = self.open_connection()?;
        conn.execute(
            "UPDATE conversation_hook_events
             SET status = 'processed', processed_at_ms = ?2, result_json = ?3, error = NULL
             WHERE id = ?1",
            params![
                event_id.trim(),
                result.processed_at_ms.unwrap_or_else(now_epoch_ms),
                serde_json::to_string(result)?,
            ],
        )?;
        Ok(())
    }

    pub fn mark_hook_event_failed(&self, event_id: &str, error: &str) -> Result<()> {
        let _guard = self.lock.lock();
        let _file_lock = self.lock_exclusive()?;
        let conn = self.open_connection()?;
        conn.execute(
            "UPDATE conversation_hook_events
             SET status = 'failed', processed_at_ms = ?2, error = ?3
             WHERE id = ?1",
            params![event_id.trim(), now_epoch_ms(), error.trim()],
        )?;
        Ok(())
    }

    fn open_connection(&self) -> Result<Connection> {
        if let Some(parent) = self.path.parent() {
            crate::state_layout::ensure_state_dir_secure(parent)?;
        }
        if let Some(parent) = self.lock_path.parent() {
            crate::state_layout::ensure_state_dir_secure(parent)?;
        }
        let conn = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
        )
        .with_context(|| format!("open {}", self.path.display()))?;
        ensure_schema(&conn)?;
        Ok(conn)
    }

    fn lock_exclusive(&self) -> Result<std::fs::File> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&self.lock_path)
            .with_context(|| format!("open {}", self.lock_path.display()))?;
        file.lock_exclusive()
            .with_context(|| format!("lock {}", self.lock_path.display()))?;
        Ok(file)
    }

    fn lock_shared(&self) -> Result<std::fs::File> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&self.lock_path)
            .with_context(|| format!("open {}", self.lock_path.display()))?;
        file.lock_shared()
            .with_context(|| format!("lock {}", self.lock_path.display()))?;
        Ok(file)
    }
}

fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA foreign_keys = ON;
         CREATE TABLE IF NOT EXISTS conversation_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS conversation_sessions (
            id TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            source_session_id TEXT,
            source_session_key TEXT NOT NULL,
            title TEXT,
            agent_id TEXT,
            transport TEXT,
            started_at_ms INTEGER NOT NULL,
            ended_at_ms INTEGER NOT NULL,
            imported_at_ms INTEGER NOT NULL,
            message_count INTEGER NOT NULL DEFAULT 0,
            capture_kind TEXT NOT NULL DEFAULT 'manual',
            raw_messages_stored INTEGER NOT NULL DEFAULT 1,
            redacted_at_ms INTEGER,
            content_digest TEXT NOT NULL,
            metadata TEXT NOT NULL
         );
         CREATE UNIQUE INDEX IF NOT EXISTS conversation_sessions_dedupe
             ON conversation_sessions(source, source_session_key, content_digest);
         CREATE INDEX IF NOT EXISTS conversation_sessions_recent
             ON conversation_sessions(ended_at_ms DESC, id);
         CREATE INDEX IF NOT EXISTS conversation_sessions_capture_recent
             ON conversation_sessions(capture_kind, imported_at_ms DESC, id);
         CREATE TABLE IF NOT EXISTS conversation_messages (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            ordinal INTEGER NOT NULL,
            role TEXT NOT NULL,
            author TEXT,
            content TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            metadata TEXT NOT NULL,
            FOREIGN KEY(session_id) REFERENCES conversation_sessions(id) ON DELETE CASCADE
         );
         CREATE INDEX IF NOT EXISTS conversation_messages_session_ordinal
             ON conversation_messages(session_id, ordinal);
         CREATE INDEX IF NOT EXISTS conversation_messages_recent
             ON conversation_messages(created_at_ms DESC, session_id);
         CREATE TABLE IF NOT EXISTS conversation_summaries (
            session_id TEXT PRIMARY KEY,
            title TEXT,
            summary TEXT NOT NULL,
            open_loops_json TEXT NOT NULL,
            open_loops_text TEXT NOT NULL,
            participants_json TEXT NOT NULL,
            latest_user_goal TEXT,
            latest_assistant_reply TEXT,
            last_message_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL,
            FOREIGN KEY(session_id) REFERENCES conversation_sessions(id) ON DELETE CASCADE
         );
         CREATE INDEX IF NOT EXISTS conversation_summaries_recent
             ON conversation_summaries(last_message_at_ms DESC, session_id);
         CREATE TABLE IF NOT EXISTS conversation_working_memory (
            agent_key TEXT PRIMARY KEY,
            agent_id TEXT,
            active_objective TEXT,
            next_step TEXT,
            open_loops_json TEXT NOT NULL,
            source_session_id TEXT NOT NULL,
            updated_at_ms INTEGER NOT NULL,
            FOREIGN KEY(source_session_id) REFERENCES conversation_sessions(id) ON DELETE CASCADE
         );
         CREATE INDEX IF NOT EXISTS conversation_working_memory_recent
             ON conversation_working_memory(updated_at_ms DESC, agent_key);
         CREATE TABLE IF NOT EXISTS conversation_diary_entries (
            id TEXT PRIMARY KEY,
            agent_key TEXT NOT NULL,
            agent_id TEXT,
            entry_type TEXT NOT NULL,
            content TEXT NOT NULL,
            source_session_id TEXT,
            created_at_ms INTEGER NOT NULL,
            metadata TEXT NOT NULL
         );
         CREATE INDEX IF NOT EXISTS conversation_diary_entries_recent
             ON conversation_diary_entries(created_at_ms DESC, id);
         CREATE INDEX IF NOT EXISTS conversation_diary_entries_agent_recent
             ON conversation_diary_entries(agent_key, created_at_ms DESC, id);
         CREATE TABLE IF NOT EXISTS conversation_hook_events (
            id TEXT PRIMARY KEY,
            action TEXT NOT NULL,
            status TEXT NOT NULL,
            source TEXT,
            source_session_id TEXT,
            agent_key TEXT NOT NULL,
            agent_id TEXT,
            queued_at_ms INTEGER NOT NULL,
            processed_at_ms INTEGER,
            payload_json TEXT NOT NULL,
            result_json TEXT,
            error TEXT
         );
         CREATE INDEX IF NOT EXISTS conversation_hook_events_recent
             ON conversation_hook_events(queued_at_ms DESC, id);
         CREATE INDEX IF NOT EXISTS conversation_hook_events_status_recent
             ON conversation_hook_events(status, queued_at_ms DESC, id);
         CREATE TABLE IF NOT EXISTS conversation_rollups (
            id TEXT PRIMARY KEY,
            agent_key TEXT NOT NULL,
            agent_id TEXT,
            title TEXT,
            summary TEXT NOT NULL,
            open_loops_json TEXT NOT NULL,
            open_loops_text TEXT NOT NULL,
            participants_json TEXT NOT NULL,
            latest_user_goal TEXT,
            latest_assistant_reply TEXT,
            source_session_ids_json TEXT NOT NULL,
            source_session_count INTEGER NOT NULL DEFAULT 0,
            window_started_at_ms INTEGER NOT NULL,
            window_ended_at_ms INTEGER NOT NULL,
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS conversation_rollups_recent
             ON conversation_rollups(updated_at_ms DESC, id);
         CREATE INDEX IF NOT EXISTS conversation_rollups_agent_recent
             ON conversation_rollups(agent_key, updated_at_ms DESC, id);",
    )?;
    ensure_column(
        conn,
        "conversation_sessions",
        "message_count",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        conn,
        "conversation_sessions",
        "capture_kind",
        "TEXT NOT NULL DEFAULT 'manual'",
    )?;
    ensure_column(
        conn,
        "conversation_sessions",
        "raw_messages_stored",
        "INTEGER NOT NULL DEFAULT 1",
    )?;
    ensure_column(conn, "conversation_sessions", "redacted_at_ms", "INTEGER")?;
    conn.execute(
        "UPDATE conversation_sessions
         SET message_count = (
            SELECT COUNT(*) FROM conversation_messages
            WHERE session_id = conversation_sessions.id
         )
         WHERE message_count <= 0",
        [],
    )?;
    conn.execute(
        "INSERT INTO conversation_meta(key, value) VALUES ('schema_version', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![CONVERSATION_SCHEMA_VERSION.to_string()],
    )?;
    Ok(())
}

fn ensure_column(conn: &Connection, table: &str, column: &str, definition: &str) -> Result<()> {
    let pragma = format!("PRAGMA table_info({table})");
    let mut stmt = conn.prepare(&pragma)?;
    let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for item in columns {
        if item?.eq_ignore_ascii_case(column) {
            return Ok(());
        }
    }
    conn.execute(
        &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
        [],
    )?;
    Ok(())
}

fn normalize_messages(messages: Vec<ConversationMessage>) -> Vec<ConversationMessage> {
    messages
        .into_iter()
        .enumerate()
        .filter_map(|(idx, mut item)| {
            let content = item.content.trim();
            if content.is_empty() {
                return None;
            }
            item.content = content.to_string();
            if item.created_at_ms.is_none() {
                item.created_at_ms = Some(now_epoch_ms() + idx as i64);
            }
            item.metadata = object_or_empty(item.metadata);
            Some(item)
        })
        .collect()
}

fn conversation_digest(
    source: &str,
    source_session_key: &str,
    messages: &[ConversationMessage],
) -> Result<String> {
    let payload = serde_json::to_vec(&json!({
        "source": source,
        "source_session_key": source_session_key,
        "messages": messages.iter().map(|item| json!({
            "role": item.role.as_str(),
            "author": item.author.as_deref().map(str::trim).filter(|value| !value.is_empty()),
            "content": item.content.trim(),
        })).collect::<Vec<_>>()
    }))?;
    Ok(hex::encode(Sha256::digest(&payload)))
}

fn store_summary(conn: &Connection, summary: &SessionSummaryRecord) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO conversation_summaries (
            session_id, title, summary, open_loops_json, open_loops_text, participants_json,
            latest_user_goal, latest_assistant_reply, last_message_at_ms, updated_at_ms
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            &summary.session_id,
            nullable_trimmed(summary.title.as_deref()),
            &summary.summary,
            serde_json::to_string(&summary.open_loops)?,
            summary.open_loops.join(" "),
            serde_json::to_string(&summary.participants)?,
            nullable_trimmed(summary.latest_user_goal.as_deref()),
            nullable_trimmed(summary.latest_assistant_reply.as_deref()),
            summary.last_message_at_ms,
            summary.updated_at_ms,
        ],
    )?;
    Ok(())
}

fn store_working_memory(conn: &Connection, item: &WorkingMemoryRecord) -> Result<()> {
    let agent_key = normalized_agent_key(item.agent_id.as_deref());
    conn.execute(
        "INSERT OR REPLACE INTO conversation_working_memory (
            agent_key, agent_id, active_objective, next_step, open_loops_json, source_session_id, updated_at_ms
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            agent_key,
            nullable_trimmed(item.agent_id.as_deref()),
            nullable_trimmed(item.active_objective.as_deref()),
            nullable_trimmed(item.next_step.as_deref()),
            serde_json::to_string(&item.open_loops)?,
            &item.source_session_id,
            item.updated_at_ms,
        ],
    )?;
    Ok(())
}

fn load_session_capture_kind(
    conn: &Connection,
    session_id: &str,
) -> Result<ConversationCaptureKind> {
    let value = conn.query_row(
        "SELECT capture_kind FROM conversation_sessions WHERE id = ?1 LIMIT 1",
        params![session_id],
        |row| row.get::<_, String>(0),
    )?;
    Ok(ConversationCaptureKind::from_str(&value))
}

fn session_raw_messages_stored(conn: &Connection, session_id: &str) -> Result<bool> {
    let value = conn.query_row(
        "SELECT raw_messages_stored FROM conversation_sessions WHERE id = ?1 LIMIT 1",
        params![session_id],
        |row| row.get::<_, i64>(0),
    )?;
    Ok(value > 0)
}

fn load_summary(conn: &Connection, session_id: &str) -> Result<Option<SessionSummaryRecord>> {
    conn.query_row(
        "SELECT session_id, title, summary, open_loops_json, participants_json, latest_user_goal,
                latest_assistant_reply, last_message_at_ms, updated_at_ms
         FROM conversation_summaries
         WHERE session_id = ?1",
        params![session_id],
        |row| {
            let open_loops_json: String = row.get(3)?;
            let participants_json: String = row.get(4)?;
            Ok(SessionSummaryRecord {
                session_id: row.get(0)?,
                title: row.get(1)?,
                summary: row.get(2)?,
                open_loops: serde_json::from_str(&open_loops_json).unwrap_or_default(),
                participants: serde_json::from_str(&participants_json).unwrap_or_default(),
                latest_user_goal: row.get(5)?,
                latest_assistant_reply: row.get(6)?,
                last_message_at_ms: row.get(7)?,
                updated_at_ms: row.get(8)?,
            })
        },
    )
    .optional()
    .context("load conversation summary")
}

fn load_working_memory(
    conn: &Connection,
    agent_id: Option<&str>,
) -> Result<Option<WorkingMemoryRecord>> {
    if let Some(agent_id) = agent_id.map(str::trim).filter(|value| !value.is_empty()) {
        return conn
            .query_row(
                "SELECT agent_id, active_objective, next_step, open_loops_json, source_session_id, updated_at_ms
                 FROM conversation_working_memory
                 WHERE agent_key = ?1
                 LIMIT 1",
                params![agent_id],
                |row| row_to_working_memory(row),
            )
            .optional()
            .context("load working memory");
    }
    conn.query_row(
        "SELECT agent_id, active_objective, next_step, open_loops_json, source_session_id, updated_at_ms
         FROM conversation_working_memory
         ORDER BY updated_at_ms DESC
         LIMIT 1",
        [],
        |row| row_to_working_memory(row),
    )
    .optional()
    .context("load working memory")
}

fn load_working_memory_for_session(
    conn: &Connection,
    session_id: &str,
) -> Result<Option<WorkingMemoryRecord>> {
    conn.query_row(
        "SELECT agent_id, active_objective, next_step, open_loops_json, source_session_id, updated_at_ms
         FROM conversation_working_memory
         WHERE source_session_id = ?1
         LIMIT 1",
        params![session_id],
        |row| row_to_working_memory(row),
    )
    .optional()
    .context("load working memory by session")
}

fn load_session_list(
    conn: &Connection,
    agent_id: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<Vec<ConversationSessionListItem>> {
    let mut items = Vec::new();
    if let Some(agent_id) = agent_id {
        let mut stmt = conn.prepare(
            "SELECT s.id, s.source, s.source_session_id, s.title, s.agent_id, s.transport,
                    s.started_at_ms, s.ended_at_ms, s.imported_at_ms, s.message_count,
                    s.capture_kind, s.raw_messages_stored, s.redacted_at_ms, s.metadata,
                    cs.session_id, cs.title, cs.summary, cs.open_loops_json, cs.participants_json,
                    cs.latest_user_goal, cs.latest_assistant_reply, cs.last_message_at_ms, cs.updated_at_ms
             FROM conversation_sessions s
             INNER JOIN conversation_summaries cs ON cs.session_id = s.id
             WHERE s.agent_id = ?1
             ORDER BY s.ended_at_ms DESC, s.id DESC
             LIMIT ?2 OFFSET ?3",
        )?;
        let rows = stmt.query_map(params![agent_id, limit as i64, offset as i64], |row| {
            row_to_session_list_item(row)
        })?;
        for row in rows {
            items.push(row?);
        }
        return Ok(items);
    }
    let mut stmt = conn.prepare(
        "SELECT s.id, s.source, s.source_session_id, s.title, s.agent_id, s.transport,
                s.started_at_ms, s.ended_at_ms, s.imported_at_ms, s.message_count,
                s.capture_kind, s.raw_messages_stored, s.redacted_at_ms, s.metadata,
                cs.session_id, cs.title, cs.summary, cs.open_loops_json, cs.participants_json,
                cs.latest_user_goal, cs.latest_assistant_reply, cs.last_message_at_ms, cs.updated_at_ms
         FROM conversation_sessions s
         INNER JOIN conversation_summaries cs ON cs.session_id = s.id
         ORDER BY s.ended_at_ms DESC, s.id DESC
         LIMIT ?1 OFFSET ?2",
    )?;
    let rows = stmt.query_map(params![limit as i64, offset as i64], |row| {
        row_to_session_list_item(row)
    })?;
    for row in rows {
        items.push(row?);
    }
    Ok(items)
}

fn load_session_record(
    conn: &Connection,
    session_id: &str,
) -> Result<Option<ConversationSessionRecord>> {
    let session = conn
        .query_row(
            "SELECT id, source, source_session_id, title, agent_id, transport,
                    started_at_ms, ended_at_ms, imported_at_ms, message_count, capture_kind,
                    raw_messages_stored, redacted_at_ms, metadata
             FROM conversation_sessions
             WHERE id = ?1
             LIMIT 1",
            params![session_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    ConversationCaptureKind::from_str(&row.get::<_, String>(10)?),
                    row.get::<_, i64>(11)? > 0,
                    row.get::<_, Option<i64>>(12)?,
                    parse_object_text(&row.get::<_, String>(13)?),
                ))
            },
        )
        .optional()
        .context("load conversation session")?;
    let Some(session) = session else {
        return Ok(None);
    };
    let summary =
        load_summary(conn, session_id)?.context("conversation session missing summary row")?;
    let working_memory = load_working_memory_for_session(conn, session_id)?;
    let mut messages = Vec::new();
    let mut stmt = conn.prepare(
        "SELECT id, ordinal, role, author, content, created_at_ms, metadata
         FROM conversation_messages
         WHERE session_id = ?1
         ORDER BY ordinal ASC",
    )?;
    let rows = stmt.query_map(params![session_id], |row| row_to_stored_message(row))?;
    for row in rows {
        messages.push(row?);
    }
    Ok(Some(ConversationSessionRecord {
        session_id: session.0,
        source: session.1,
        source_session_id: session.2,
        title: session.3,
        agent_id: session.4,
        transport: session.5,
        started_at_ms: session.6,
        ended_at_ms: session.7,
        imported_at_ms: session.8,
        message_count: session.9.max(0) as usize,
        capture_kind: session.10,
        raw_messages_stored: session.11,
        redacted_at_ms: session.12,
        metadata: session.13,
        summary,
        working_memory,
        messages,
    }))
}

fn load_diary_entries(
    conn: &Connection,
    agent_id: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<Vec<DiaryEntryRecord>> {
    let mut entries = Vec::new();
    if let Some(agent_key) = agent_id {
        let mut stmt = conn.prepare(
            "SELECT id, agent_id, entry_type, content, source_session_id, created_at_ms, metadata
             FROM conversation_diary_entries
             WHERE agent_key = ?1
             ORDER BY created_at_ms DESC, id DESC
             LIMIT ?2 OFFSET ?3",
        )?;
        let rows = stmt.query_map(params![agent_key, limit as i64, offset as i64], |row| {
            row_to_diary_entry(row)
        })?;
        for row in rows {
            entries.push(row?);
        }
        return Ok(entries);
    }
    let mut stmt = conn.prepare(
        "SELECT id, agent_id, entry_type, content, source_session_id, created_at_ms, metadata
         FROM conversation_diary_entries
         ORDER BY created_at_ms DESC, id DESC
         LIMIT ?1 OFFSET ?2",
    )?;
    let rows = stmt.query_map(params![limit as i64, offset as i64], |row| {
        row_to_diary_entry(row)
    })?;
    for row in rows {
        entries.push(row?);
    }
    Ok(entries)
}

fn load_diary_entries_for_session(
    conn: &Connection,
    session_id: &str,
) -> Result<Vec<DiaryEntryRecord>> {
    let mut entries = Vec::new();
    let mut stmt = conn.prepare(
        "SELECT id, agent_id, entry_type, content, source_session_id, created_at_ms, metadata
         FROM conversation_diary_entries
         WHERE source_session_id = ?1
         ORDER BY created_at_ms DESC, id DESC",
    )?;
    let rows = stmt.query_map(params![session_id], |row| row_to_diary_entry(row))?;
    for row in rows {
        entries.push(row?);
    }
    Ok(entries)
}

fn session_ids_older_than(
    conn: &Connection,
    capture_kind: ConversationCaptureKind,
    retention_days: u32,
    now_ms: i64,
) -> Result<Vec<String>> {
    if retention_days == 0 {
        return Ok(Vec::new());
    }
    let cutoff = now_ms.saturating_sub(millis_for_days(retention_days));
    let mut stmt = conn.prepare(
        "SELECT id
         FROM conversation_sessions
         WHERE capture_kind = ?1 AND imported_at_ms < ?2",
    )?;
    let rows = stmt.query_map(params![capture_kind.as_str(), cutoff], |row| {
        row.get::<_, String>(0)
    })?;
    let mut ids = Vec::new();
    for row in rows {
        ids.push(row?);
    }
    Ok(ids)
}

fn count_diary_entries_older_than(
    conn: &Connection,
    retention_days: u32,
    now_ms: i64,
) -> Result<usize> {
    if retention_days == 0 {
        return Ok(0);
    }
    let cutoff = now_ms.saturating_sub(millis_for_days(retention_days));
    let count = conn.query_row(
        "SELECT COUNT(*) FROM conversation_diary_entries WHERE created_at_ms < ?1",
        params![cutoff],
        |row| row.get::<_, i64>(0),
    )?;
    Ok(count.max(0) as usize)
}

fn count_hook_events_older_than(
    conn: &Connection,
    retention_days: u32,
    now_ms: i64,
) -> Result<usize> {
    if retention_days == 0 {
        return Ok(0);
    }
    let cutoff = now_ms.saturating_sub(millis_for_days(retention_days));
    let count = conn.query_row(
        "SELECT COUNT(*) FROM conversation_hook_events WHERE queued_at_ms < ?1",
        params![cutoff],
        |row| row.get::<_, i64>(0),
    )?;
    Ok(count.max(0) as usize)
}

fn delete_diary_entries_older_than(
    conn: &Connection,
    retention_days: u32,
    now_ms: i64,
) -> Result<()> {
    if retention_days == 0 {
        return Ok(());
    }
    let cutoff = now_ms.saturating_sub(millis_for_days(retention_days));
    conn.execute(
        "DELETE FROM conversation_diary_entries WHERE created_at_ms < ?1",
        params![cutoff],
    )?;
    Ok(())
}

fn delete_hook_events_older_than(
    conn: &Connection,
    retention_days: u32,
    now_ms: i64,
) -> Result<()> {
    if retention_days == 0 {
        return Ok(());
    }
    let cutoff = now_ms.saturating_sub(millis_for_days(retention_days));
    conn.execute(
        "DELETE FROM conversation_hook_events WHERE queued_at_ms < ?1",
        params![cutoff],
    )?;
    Ok(())
}

fn detach_diary_entries_for_sessions(conn: &Connection, session_ids: &[String]) -> Result<()> {
    for session_id in session_ids {
        conn.execute(
            "UPDATE conversation_diary_entries
             SET source_session_id = NULL
             WHERE source_session_id = ?1",
            params![session_id],
        )?;
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct ConversationRollupRecord {
    id: String,
    agent_key: String,
    agent_id: Option<String>,
    title: Option<String>,
    summary: String,
    open_loops_json: String,
    open_loops_text: String,
    participants_json: String,
    latest_user_goal: Option<String>,
    latest_assistant_reply: Option<String>,
    source_session_ids_json: String,
    source_session_count: usize,
    window_started_at_ms: i64,
    window_ended_at_ms: i64,
    created_at_ms: i64,
    updated_at_ms: i64,
}

#[derive(Debug, Clone)]
struct RollupSourceSession {
    session_id: String,
    agent_id: Option<String>,
    title: Option<String>,
    summary: String,
    open_loops: Vec<String>,
    participants: Vec<String>,
    latest_user_goal: Option<String>,
    latest_assistant_reply: Option<String>,
    started_at_ms: i64,
    ended_at_ms: i64,
}

fn working_memory_agent_keys_for_cleanup(
    conn: &Connection,
    deleted_session_ids: &[String],
    retention_days: u32,
    now_ms: i64,
) -> Result<Vec<String>> {
    let mut agent_keys = HashSet::new();
    for session_id in deleted_session_ids {
        let mut stmt = conn.prepare(
            "SELECT agent_key
             FROM conversation_working_memory
             WHERE source_session_id = ?1",
        )?;
        let rows = stmt.query_map(params![session_id], |row| row.get::<_, String>(0))?;
        for row in rows {
            agent_keys.insert(row?);
        }
    }
    if retention_days > 0 {
        let cutoff = now_ms.saturating_sub(millis_for_days(retention_days));
        let mut stmt = conn.prepare(
            "SELECT agent_key
             FROM conversation_working_memory
             WHERE updated_at_ms < ?1",
        )?;
        let rows = stmt.query_map(params![cutoff], |row| row.get::<_, String>(0))?;
        for row in rows {
            agent_keys.insert(row?);
        }
    }
    let mut items = agent_keys.into_iter().collect::<Vec<_>>();
    items.sort();
    Ok(items)
}

fn delete_working_memory_records(conn: &Connection, agent_keys: &[String]) -> Result<()> {
    for agent_key in agent_keys {
        conn.execute(
            "DELETE FROM conversation_working_memory WHERE agent_key = ?1",
            params![agent_key],
        )?;
    }
    Ok(())
}

fn count_rollups_older_than(conn: &Connection, retention_days: u32, now_ms: i64) -> Result<usize> {
    if retention_days == 0 {
        return Ok(0);
    }
    let cutoff = now_ms.saturating_sub(millis_for_days(retention_days));
    let count = conn.query_row(
        "SELECT COUNT(*) FROM conversation_rollups WHERE updated_at_ms < ?1",
        params![cutoff],
        |row| row.get::<_, i64>(0),
    )?;
    Ok(count.max(0) as usize)
}

fn load_rollup_source_sessions(
    conn: &Connection,
    session_ids: &[String],
) -> Result<Vec<RollupSourceSession>> {
    let mut items = Vec::new();
    for session_id in session_ids {
        let Some(session) = conn
            .query_row(
                "SELECT s.id, s.agent_id, s.title, cs.summary, cs.open_loops_json, cs.participants_json,
                        cs.latest_user_goal, cs.latest_assistant_reply, s.started_at_ms, s.ended_at_ms
                 FROM conversation_sessions s
                 LEFT JOIN conversation_summaries cs ON cs.session_id = s.id
                 WHERE s.id = ?1
                 LIMIT 1",
                params![session_id],
                |row| {
                    let open_loops_json: Option<String> = row.get(4)?;
                    let participants_json: Option<String> = row.get(5)?;
                    Ok(RollupSourceSession {
                        session_id: row.get(0)?,
                        agent_id: row.get(1)?,
                        title: row.get(2)?,
                        summary: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                        open_loops: open_loops_json
                            .as_deref()
                            .and_then(|value| serde_json::from_str::<Vec<String>>(value).ok())
                            .unwrap_or_default(),
                        participants: participants_json
                            .as_deref()
                            .and_then(|value| serde_json::from_str::<Vec<String>>(value).ok())
                            .unwrap_or_default(),
                        latest_user_goal: row.get(6)?,
                        latest_assistant_reply: row.get(7)?,
                        started_at_ms: row.get(8)?,
                        ended_at_ms: row.get(9)?,
                    })
                },
            )
            .optional()?
        else {
            continue;
        };
        items.push(session);
    }
    Ok(items)
}

fn build_rollup_records(
    sessions: Vec<RollupSourceSession>,
    now_ms: i64,
) -> Result<Vec<ConversationRollupRecord>> {
    if sessions.is_empty() {
        return Ok(Vec::new());
    }

    let mut grouped: HashMap<String, Vec<RollupSourceSession>> = HashMap::new();
    for session in sessions {
        grouped
            .entry(normalized_agent_key(session.agent_id.as_deref()))
            .or_default()
            .push(session);
    }

    let mut rollups = Vec::new();
    for (agent_key, mut items) in grouped {
        items.sort_by(|left, right| {
            left.started_at_ms
                .cmp(&right.started_at_ms)
                .then_with(|| left.session_id.cmp(&right.session_id))
        });
        let source_session_ids = items
            .iter()
            .map(|item| item.session_id.clone())
            .collect::<Vec<_>>();
        let source_session_count = source_session_ids.len();
        let title = Some(format!(
            "Archived {source_session_count} conversation session{}",
            if source_session_count == 1 { "" } else { "s" }
        ));
        let mut open_loops = Vec::new();
        let mut participants = Vec::new();
        let mut fragments = Vec::new();
        let mut latest_user_goal = None;
        let mut latest_assistant_reply = None;
        let latest_item = items
            .iter()
            .max_by(|left, right| left.ended_at_ms.cmp(&right.ended_at_ms))
            .cloned();

        for item in &items {
            push_unique_strings(&mut open_loops, item.open_loops.iter().cloned());
            push_unique_strings(&mut participants, item.participants.iter().cloned());
        }
        if let Some(item) = latest_item.as_ref() {
            latest_user_goal = item.latest_user_goal.clone();
            latest_assistant_reply = item.latest_assistant_reply.clone();
        }
        for item in items.iter().rev().take(3) {
            let summary = item.summary.trim();
            if summary.is_empty() {
                continue;
            }
            let label = item
                .title
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("session");
            fragments.push(format!("{label}: {summary}"));
        }
        let window_started_at_ms = items
            .iter()
            .map(|item| item.started_at_ms)
            .min()
            .unwrap_or(now_ms);
        let window_ended_at_ms = items
            .iter()
            .map(|item| item.ended_at_ms)
            .max()
            .unwrap_or(now_ms);
        let summary = if fragments.is_empty() {
            format!(
                "Archived {source_session_count} conversation session{} for continuity between {} and {}.",
                if source_session_count == 1 { "" } else { "s" },
                window_started_at_ms,
                window_ended_at_ms
            )
        } else {
            format!(
                "Archived {source_session_count} conversation session{} for continuity between {} and {}. Recent context: {}",
                if source_session_count == 1 { "" } else { "s" },
                window_started_at_ms,
                window_ended_at_ms,
                fragments.join(" | ")
            )
        };
        rollups.push(ConversationRollupRecord {
            id: Uuid::new_v4().to_string(),
            agent_key,
            agent_id: items.iter().find_map(|item| item.agent_id.clone()),
            title,
            summary,
            open_loops_json: serde_json::to_string(&open_loops)?,
            open_loops_text: open_loops.join("\n"),
            participants_json: serde_json::to_string(&participants)?,
            latest_user_goal,
            latest_assistant_reply,
            source_session_ids_json: serde_json::to_string(&source_session_ids)?,
            source_session_count,
            window_started_at_ms,
            window_ended_at_ms,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
        });
    }
    rollups.sort_by(|left, right| {
        right
            .window_ended_at_ms
            .cmp(&left.window_ended_at_ms)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(rollups)
}

fn store_rollups(conn: &Connection, rollups: &[ConversationRollupRecord]) -> Result<()> {
    for rollup in rollups {
        conn.execute(
            "INSERT INTO conversation_rollups (
                id, agent_key, agent_id, title, summary, open_loops_json, open_loops_text,
                participants_json, latest_user_goal, latest_assistant_reply, source_session_ids_json,
                source_session_count, window_started_at_ms, window_ended_at_ms, created_at_ms,
                updated_at_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                &rollup.id,
                &rollup.agent_key,
                nullable_trimmed(rollup.agent_id.as_deref()),
                nullable_trimmed(rollup.title.as_deref()),
                &rollup.summary,
                &rollup.open_loops_json,
                &rollup.open_loops_text,
                &rollup.participants_json,
                nullable_trimmed(rollup.latest_user_goal.as_deref()),
                nullable_trimmed(rollup.latest_assistant_reply.as_deref()),
                &rollup.source_session_ids_json,
                rollup.source_session_count as i64,
                rollup.window_started_at_ms,
                rollup.window_ended_at_ms,
                rollup.created_at_ms,
                rollup.updated_at_ms,
            ],
        )?;
    }
    Ok(())
}

fn delete_rollups_older_than(conn: &Connection, retention_days: u32, now_ms: i64) -> Result<()> {
    if retention_days == 0 {
        return Ok(());
    }
    let cutoff = now_ms.saturating_sub(millis_for_days(retention_days));
    conn.execute(
        "DELETE FROM conversation_rollups WHERE updated_at_ms < ?1",
        params![cutoff],
    )?;
    Ok(())
}

fn push_unique_strings<I>(target: &mut Vec<String>, values: I)
where
    I: IntoIterator<Item = String>,
{
    let mut seen = target.iter().cloned().collect::<HashSet<_>>();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        if seen.insert(trimmed.to_string()) {
            target.push(trimmed.to_string());
        }
    }
}

fn load_recent_summaries(
    conn: &Connection,
    query: Option<&str>,
    limit: usize,
) -> Result<(Vec<SessionSummaryRecord>, usize, bool)> {
    let mut items = load_recent_session_summaries(conn, query, limit)?;
    items.extend(load_recent_rollup_summaries(conn, query, limit)?);
    if items.is_empty() && query.is_some() {
        return load_recent_summaries(conn, None, limit);
    }
    items.sort_by(|left, right| {
        right
            .last_message_at_ms
            .cmp(&left.last_message_at_ms)
            .then_with(|| left.session_id.cmp(&right.session_id))
    });
    let total = count_recent_session_summaries(conn, query)?
        .saturating_add(count_recent_rollup_summaries(conn, query)?);
    items.truncate(limit);
    let found = !items.is_empty();
    Ok((items, total, found))
}

fn count_recent_session_summaries(conn: &Connection, query: Option<&str>) -> Result<usize> {
    let total = if let Some(query) = query {
        conn.query_row(
            "SELECT COUNT(*)
             FROM conversation_summaries cs
             INNER JOIN conversation_sessions s ON s.id = cs.session_id
             WHERE s.redacted_at_ms IS NULL
               AND instr(lower(cs.summary || ' ' || cs.open_loops_text), lower(?1)) > 0",
            params![query],
            |row| row.get::<_, i64>(0),
        )?
    } else {
        conn.query_row(
            "SELECT COUNT(*)
             FROM conversation_summaries cs
             INNER JOIN conversation_sessions s ON s.id = cs.session_id
             WHERE s.redacted_at_ms IS NULL",
            [],
            |row| row.get::<_, i64>(0),
        )?
    };
    Ok(total.max(0) as usize)
}

fn load_recent_session_summaries(
    conn: &Connection,
    query: Option<&str>,
    limit: usize,
) -> Result<Vec<SessionSummaryRecord>> {
    let mut items = Vec::new();
    if let Some(query) = query {
        let mut stmt = conn.prepare(
            "SELECT cs.session_id, cs.title, cs.summary, cs.open_loops_json, cs.participants_json,
                    cs.latest_user_goal, cs.latest_assistant_reply, cs.last_message_at_ms, cs.updated_at_ms
             FROM conversation_summaries cs
             INNER JOIN conversation_sessions s ON s.id = cs.session_id
             WHERE s.redacted_at_ms IS NULL
               AND instr(lower(cs.summary || ' ' || cs.open_loops_text), lower(?1)) > 0
             ORDER BY cs.last_message_at_ms DESC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![query, limit as i64], |row| row_to_summary(row))?;
        for row in rows {
            items.push(row?);
        }
    } else {
        let mut stmt = conn.prepare(
            "SELECT cs.session_id, cs.title, cs.summary, cs.open_loops_json, cs.participants_json,
                    cs.latest_user_goal, cs.latest_assistant_reply, cs.last_message_at_ms, cs.updated_at_ms
             FROM conversation_summaries cs
             INNER JOIN conversation_sessions s ON s.id = cs.session_id
             WHERE s.redacted_at_ms IS NULL
             ORDER BY cs.last_message_at_ms DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| row_to_summary(row))?;
        for row in rows {
            items.push(row?);
        }
    }
    Ok(items)
}

fn count_recent_rollup_summaries(conn: &Connection, query: Option<&str>) -> Result<usize> {
    let total = if let Some(query) = query {
        conn.query_row(
            "SELECT COUNT(*)
             FROM conversation_rollups
             WHERE instr(lower(summary || ' ' || open_loops_text), lower(?1)) > 0",
            params![query],
            |row| row.get::<_, i64>(0),
        )?
    } else {
        conn.query_row("SELECT COUNT(*) FROM conversation_rollups", [], |row| {
            row.get::<_, i64>(0)
        })?
    };
    Ok(total.max(0) as usize)
}

fn load_recent_rollup_summaries(
    conn: &Connection,
    query: Option<&str>,
    limit: usize,
) -> Result<Vec<SessionSummaryRecord>> {
    let mut items = Vec::new();
    if let Some(query) = query {
        let mut stmt = conn.prepare(
            "SELECT id AS session_id, title, summary, open_loops_json, participants_json,
                    latest_user_goal, latest_assistant_reply, window_ended_at_ms AS last_message_at_ms,
                    updated_at_ms
             FROM conversation_rollups
             WHERE instr(lower(summary || ' ' || open_loops_text), lower(?1)) > 0
             ORDER BY window_ended_at_ms DESC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![query, limit as i64], |row| row_to_summary(row))?;
        for row in rows {
            items.push(row?);
        }
    } else {
        let mut stmt = conn.prepare(
            "SELECT id AS session_id, title, summary, open_loops_json, participants_json,
                    latest_user_goal, latest_assistant_reply, window_ended_at_ms AS last_message_at_ms,
                    updated_at_ms
             FROM conversation_rollups
             ORDER BY window_ended_at_ms DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| row_to_summary(row))?;
        for row in rows {
            items.push(row?);
        }
    }
    Ok(items)
}

fn load_search_summary_hits(
    conn: &Connection,
    query: &str,
    agent_id: Option<&str>,
) -> Result<Vec<ConversationSearchHit>> {
    let mut stmt = conn.prepare(
        "SELECT s.id, s.source, s.source_session_id, s.title, s.agent_id, s.ended_at_ms, s.imported_at_ms,
                cs.session_id, cs.title, cs.summary, cs.open_loops_json, cs.participants_json,
                cs.latest_user_goal, cs.latest_assistant_reply, cs.last_message_at_ms, cs.updated_at_ms
         FROM conversation_sessions s
         INNER JOIN conversation_summaries cs ON cs.session_id = s.id
         WHERE (?1 IS NULL OR s.agent_id = ?1)
           AND s.redacted_at_ms IS NULL
           AND (
                instr(lower(coalesce(s.title, '')), lower(?2)) > 0
                OR instr(lower(cs.summary), lower(?2)) > 0
                OR instr(lower(cs.open_loops_text), lower(?2)) > 0
                OR instr(lower(coalesce(cs.latest_user_goal, '')), lower(?2)) > 0
                OR instr(lower(coalesce(cs.latest_assistant_reply, '')), lower(?2)) > 0
           )
         ORDER BY s.ended_at_ms DESC, s.id DESC",
    )?;
    let rows = stmt.query_map(params![agent_id, query], |row| {
        let summary = row_to_summary_with_offset(row, 7)?;
        let session_id: String = row.get(0)?;
        let title: Option<String> = row.get(3)?;
        let latest_user_goal = summary.latest_user_goal.clone().unwrap_or_default();
        let latest_assistant_reply = summary.latest_assistant_reply.clone().unwrap_or_default();
        let open_loops_text = summary.open_loops.join("\n");
        let (matched_field, snippet, score) = first_summary_match(
            query,
            title.as_deref().unwrap_or_default(),
            &summary.summary,
            &open_loops_text,
            &latest_user_goal,
            &latest_assistant_reply,
        );
        Ok(ConversationSearchHit {
            session_id,
            source: row.get(1)?,
            source_session_id: row.get(2)?,
            title,
            agent_id: row.get(4)?,
            ended_at_ms: row.get(5)?,
            imported_at_ms: row.get(6)?,
            summary,
            matched_field: matched_field.to_string(),
            snippet,
            score,
            message_id: None,
            role: None,
        })
    })?;
    let mut hits = Vec::new();
    for row in rows {
        hits.push(row?);
    }
    Ok(hits)
}

fn load_search_message_hits(
    conn: &Connection,
    query: &str,
    agent_id: Option<&str>,
) -> Result<Vec<ConversationSearchHit>> {
    let mut stmt = conn.prepare(
        "SELECT s.id, s.source, s.source_session_id, s.title, s.agent_id, s.ended_at_ms, s.imported_at_ms,
                cs.session_id, cs.title, cs.summary, cs.open_loops_json, cs.participants_json,
                cs.latest_user_goal, cs.latest_assistant_reply, cs.last_message_at_ms, cs.updated_at_ms,
                cm.id, cm.role, cm.content
         FROM conversation_sessions s
         INNER JOIN conversation_summaries cs ON cs.session_id = s.id
         INNER JOIN conversation_messages cm ON cm.session_id = s.id
         WHERE (?1 IS NULL OR s.agent_id = ?1)
           AND s.redacted_at_ms IS NULL
           AND instr(lower(cm.content), lower(?2)) > 0
         ORDER BY cm.created_at_ms DESC, cm.id DESC",
    )?;
    let rows = stmt.query_map(params![agent_id, query], |row| {
        let summary = row_to_summary_with_offset(row, 7)?;
        let content: String = row.get(18)?;
        Ok(ConversationSearchHit {
            session_id: row.get(0)?,
            source: row.get(1)?,
            source_session_id: row.get(2)?,
            title: row.get(3)?,
            agent_id: row.get(4)?,
            ended_at_ms: row.get(5)?,
            imported_at_ms: row.get(6)?,
            summary,
            matched_field: "message".to_string(),
            snippet: build_match_snippet(&content, query),
            score: 180,
            message_id: row.get(16)?,
            role: row.get(17)?,
        })
    })?;
    let mut hits = Vec::new();
    for row in rows {
        hits.push(row?);
    }
    Ok(hits)
}

fn load_transcript_snippets(
    conn: &Connection,
    query: &str,
    limit: usize,
) -> Result<(Vec<TranscriptSnippet>, usize, bool)> {
    if limit == 0 {
        return Ok((Vec::new(), 0, false));
    }
    let total = conn
        .query_row(
            "SELECT COUNT(*)
             FROM conversation_messages cm
             INNER JOIN conversation_sessions s ON s.id = cm.session_id
             WHERE s.redacted_at_ms IS NULL
               AND instr(lower(cm.content), lower(?1)) > 0",
            params![query],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0);
    let mut stmt = conn.prepare(
        "SELECT cm.session_id, cm.id, cm.role, cm.content, cm.created_at_ms
         FROM conversation_messages cm
         INNER JOIN conversation_sessions s ON s.id = cm.session_id
         WHERE s.redacted_at_ms IS NULL
           AND instr(lower(cm.content), lower(?1)) > 0
         ORDER BY cm.created_at_ms DESC
         LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![query, limit as i64], |row| {
        Ok(TranscriptSnippet {
            session_id: row.get(0)?,
            message_id: row.get(1)?,
            role: row.get(2)?,
            content: row.get(3)?,
            created_at_ms: row.get(4)?,
        })
    })?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row?);
    }
    let found = !items.is_empty();
    Ok((items, total.max(0) as usize, found))
}

fn first_summary_match<'a>(
    query: &str,
    title: &'a str,
    summary: &'a str,
    open_loops: &'a str,
    latest_user_goal: &'a str,
    latest_assistant_reply: &'a str,
) -> (&'static str, String, i64) {
    let fields = [
        ("title", title, 320),
        ("summary", summary, 260),
        ("open_loops", open_loops, 240),
        ("latest_user_goal", latest_user_goal, 220),
        ("latest_assistant_reply", latest_assistant_reply, 200),
    ];
    for (field, text, score) in fields {
        if contains_case_insensitive(text, query) {
            return (field, build_match_snippet(text, query), score);
        }
    }
    ("summary", build_match_snippet(summary, query), 160)
}

fn build_match_snippet(text: &str, query: &str) -> String {
    const MAX_SNIPPET_CHARS: usize = 180;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.len() <= MAX_SNIPPET_CHARS {
        return trimmed.to_string();
    }
    let lower_text = trimmed.to_ascii_lowercase();
    let lower_query = query.trim().to_ascii_lowercase();
    let match_idx = lower_text.find(&lower_query).unwrap_or(0);
    let window_start =
        floor_char_boundary(trimmed, match_idx.saturating_sub(MAX_SNIPPET_CHARS / 3));
    let window_end = ceil_char_boundary(
        trimmed,
        (window_start + MAX_SNIPPET_CHARS).min(trimmed.len()),
    );
    let mut snippet = trimmed[window_start..window_end].trim().to_string();
    if window_start > 0 {
        snippet = format!("...{snippet}");
    }
    if window_end < trimmed.len() {
        snippet.push_str("...");
    }
    snippet
}

fn contains_case_insensitive(text: &str, query: &str) -> bool {
    text.to_ascii_lowercase()
        .contains(&query.trim().to_ascii_lowercase())
}

fn floor_char_boundary(text: &str, mut idx: usize) -> usize {
    idx = idx.min(text.len());
    while idx > 0 && !text.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

fn ceil_char_boundary(text: &str, mut idx: usize) -> usize {
    idx = idx.min(text.len());
    while idx < text.len() && !text.is_char_boundary(idx) {
        idx += 1;
    }
    idx
}

fn compare_search_hits(left: &ConversationSearchHit, right: &ConversationSearchHit) -> Ordering {
    right
        .score
        .cmp(&left.score)
        .then_with(|| right.ended_at_ms.cmp(&left.ended_at_ms))
        .then_with(|| right.imported_at_ms.cmp(&left.imported_at_ms))
        .then_with(|| left.session_id.cmp(&right.session_id))
}

fn is_better_search_hit(
    candidate: &ConversationSearchHit,
    existing: &ConversationSearchHit,
) -> bool {
    compare_search_hits(candidate, existing) == Ordering::Less
}

fn row_to_summary(row: &rusqlite::Row<'_>) -> rusqlite::Result<SessionSummaryRecord> {
    row_to_summary_with_offset(row, 0)
}

fn row_to_summary_with_offset(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> rusqlite::Result<SessionSummaryRecord> {
    let open_loops_json: String = row.get(offset + 3)?;
    let participants_json: String = row.get(offset + 4)?;
    Ok(SessionSummaryRecord {
        session_id: row.get(offset)?,
        title: row.get(offset + 1)?,
        summary: row.get(offset + 2)?,
        open_loops: serde_json::from_str(&open_loops_json).unwrap_or_default(),
        participants: serde_json::from_str(&participants_json).unwrap_or_default(),
        latest_user_goal: row.get(offset + 5)?,
        latest_assistant_reply: row.get(offset + 6)?,
        last_message_at_ms: row.get(offset + 7)?,
        updated_at_ms: row.get(offset + 8)?,
    })
}

fn row_to_working_memory(row: &rusqlite::Row<'_>) -> rusqlite::Result<WorkingMemoryRecord> {
    let open_loops_json: String = row.get(3)?;
    Ok(WorkingMemoryRecord {
        agent_id: row.get(0)?,
        active_objective: row.get(1)?,
        next_step: row.get(2)?,
        open_loops: serde_json::from_str(&open_loops_json).unwrap_or_default(),
        source_session_id: row.get(4)?,
        updated_at_ms: row.get(5)?,
    })
}

fn row_to_session_list_item(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<ConversationSessionListItem> {
    Ok(ConversationSessionListItem {
        session_id: row.get(0)?,
        source: row.get(1)?,
        source_session_id: row.get(2)?,
        title: row.get(3)?,
        agent_id: row.get(4)?,
        transport: row.get(5)?,
        started_at_ms: row.get(6)?,
        ended_at_ms: row.get(7)?,
        imported_at_ms: row.get(8)?,
        message_count: row.get::<_, i64>(9)?.max(0) as usize,
        capture_kind: ConversationCaptureKind::from_str(&row.get::<_, String>(10)?),
        raw_messages_stored: row.get::<_, i64>(11)? > 0,
        redacted_at_ms: row.get(12)?,
        metadata: parse_object_text(&row.get::<_, String>(13)?),
        summary: row_to_summary_with_offset(row, 14)?,
    })
}

fn row_to_stored_message(row: &rusqlite::Row<'_>) -> rusqlite::Result<ConversationStoredMessage> {
    Ok(ConversationStoredMessage {
        message_id: row.get(0)?,
        ordinal: row.get::<_, i64>(1)?.max(0) as usize,
        role: row.get(2)?,
        author: row.get(3)?,
        content: row.get(4)?,
        created_at_ms: row.get(5)?,
        metadata: parse_object_text(&row.get::<_, String>(6)?),
    })
}

fn row_to_diary_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<DiaryEntryRecord> {
    Ok(DiaryEntryRecord {
        entry_id: row.get(0)?,
        agent_id: row.get(1)?,
        entry_type: row.get(2)?,
        content: row.get(3)?,
        source_session_id: row.get(4)?,
        created_at_ms: row.get(5)?,
        metadata: parse_object_text(&row.get::<_, String>(6)?),
    })
}

fn normalized_agent_key(value: Option<&str>) -> String {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("__default__")
        .to_string()
}

fn nullable_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn parse_object_text(input: &str) -> Value {
    match serde_json::from_str::<Value>(input) {
        Ok(value) => object_or_empty(value),
        Err(_) => json!({}),
    }
}

fn object_or_empty(value: Value) -> Value {
    match value {
        Value::Object(_) => value,
        _ => json!({}),
    }
}

fn now_epoch_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

fn millis_for_days(days: u32) -> i64 {
    i64::from(days)
        .saturating_mul(24)
        .saturating_mul(60)
        .saturating_mul(60)
        .saturating_mul(1000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversations::types::{
        ConversationCaptureKind, ConversationHookAction, ConversationHookPayload,
        ConversationImport, ConversationImportOptions, ConversationRetentionPolicy,
        ConversationRole,
    };
    use serde_json::json;
    use tempfile::tempdir;

    fn import_fixture() -> ConversationImport {
        ConversationImport {
            source: "manual".to_string(),
            source_session_id: Some("fixture-1".to_string()),
            title: Some("Wake-up rollout".to_string()),
            agent_id: Some("codex".to_string()),
            transport: Some("http".to_string()),
            started_at_ms: Some(10),
            ended_at_ms: Some(30),
            messages: vec![
                ConversationMessage {
                    role: ConversationRole::User,
                    content: "We need wake-up memory in chat.".to_string(),
                    author: Some("bekir".to_string()),
                    created_at_ms: Some(10),
                    metadata: json!({}),
                },
                ConversationMessage {
                    role: ConversationRole::Assistant,
                    content: "Next step: add the import endpoint.".to_string(),
                    author: Some("codex".to_string()),
                    created_at_ms: Some(20),
                    metadata: json!({}),
                },
            ],
            metadata: json!({"source_file": "fixture.json"}),
        }
    }

    #[test]
    fn imports_and_deduplicates_sessions() -> Result<()> {
        let dir = tempdir()?;
        let store = ConversationStore::new(dir.path());

        let first = store.import_session(import_fixture())?;
        let second = store.import_session(import_fixture())?;

        assert!(!first.deduplicated);
        assert!(second.deduplicated);
        assert_eq!(first.session_id, second.session_id);
        Ok(())
    }

    #[test]
    fn imports_without_raw_archive_and_preserves_message_count() -> Result<()> {
        let dir = tempdir()?;
        let store = ConversationStore::new(dir.path());
        let imported = store.import_session_with_options(
            import_fixture(),
            ConversationImportOptions {
                capture_kind: ConversationCaptureKind::Manual,
                store_raw_messages: false,
            },
        )?;

        assert!(!imported.raw_messages_stored);
        let session = store
            .read_session(&imported.session_id)?
            .expect("session should exist");
        assert_eq!(session.message_count, 2);
        assert!(!session.raw_messages_stored);
        assert!(session.messages.is_empty());
        Ok(())
    }

    #[test]
    fn builds_wakeup_bundle_from_recent_state() -> Result<()> {
        let dir = tempdir()?;
        let store = ConversationStore::new(dir.path());
        let imported = store.import_session(import_fixture())?;

        let wakeup = store.build_wakeup_bundle(Some("codex"), Some("import"), 3, 2)?;

        assert_eq!(
            wakeup
                .working_memory
                .as_ref()
                .and_then(|item| item.agent_id.as_deref()),
            Some("codex")
        );
        assert_eq!(wakeup.episodic_summaries[0].session_id, imported.session_id);
        assert!(!wakeup.transcript_snippets.is_empty());
        Ok(())
    }

    #[test]
    fn lists_reads_and_deletes_sessions() -> Result<()> {
        let dir = tempdir()?;
        let store = ConversationStore::new(dir.path());
        let first = store.import_session(import_fixture())?;
        let mut second_import = import_fixture();
        second_import.source_session_id = Some("fixture-2".to_string());
        second_import.title = Some("Follow-up".to_string());
        second_import.agent_id = Some("reviewer".to_string());
        second_import.started_at_ms = Some(40);
        second_import.ended_at_ms = Some(50);
        let second = store.import_session(second_import)?;

        let list = store.list_sessions(None, 10, 0)?;
        assert_eq!(list.total, 2);
        assert_eq!(list.sessions.len(), 2);
        assert_eq!(list.sessions[0].session_id, second.session_id);
        assert_eq!(list.sessions[1].session_id, first.session_id);

        let filtered = store.list_sessions(Some("codex"), 10, 0)?;
        assert_eq!(filtered.total, 1);
        assert_eq!(filtered.sessions[0].session_id, first.session_id);

        let session = store
            .read_session(&first.session_id)?
            .expect("session should exist");
        assert_eq!(session.summary.session_id, first.session_id);
        assert_eq!(session.messages.len(), first.message_count);
        assert_eq!(session.messages[0].ordinal, 0);
        assert_eq!(session.messages[0].role, "user");

        assert!(store.delete_session(&first.session_id)?);
        assert!(!store.delete_session(&first.session_id)?);
        assert!(store.read_session(&first.session_id)?.is_none());

        let after_delete = store.list_sessions(None, 10, 0)?;
        assert_eq!(after_delete.total, 1);
        assert_eq!(after_delete.sessions[0].session_id, second.session_id);
        Ok(())
    }

    #[test]
    fn searches_sessions_across_summary_and_messages() -> Result<()> {
        let dir = tempdir()?;
        let store = ConversationStore::new(dir.path());
        store.import_session(import_fixture())?;
        let mut second = import_fixture();
        second.source_session_id = Some("fixture-3".to_string());
        second.title = Some("Importer follow-up".to_string());
        second.messages = vec![
            ConversationMessage {
                role: ConversationRole::User,
                content: "Please add native Codex import support.".to_string(),
                author: None,
                created_at_ms: Some(40),
                metadata: json!({}),
            },
            ConversationMessage {
                role: ConversationRole::Assistant,
                content: "Noted. Search anchor alpha-token-42.".to_string(),
                author: None,
                created_at_ms: Some(50),
                metadata: json!({}),
            },
            ConversationMessage {
                role: ConversationRole::User,
                content: "Also wire the HTTP endpoint.".to_string(),
                author: None,
                created_at_ms: Some(60),
                metadata: json!({}),
            },
            ConversationMessage {
                role: ConversationRole::Assistant,
                content: "Next step: add archive search across messages.".to_string(),
                author: None,
                created_at_ms: Some(70),
                metadata: json!({}),
            },
        ];
        store.import_session(second)?;

        let search = store.search_sessions("alpha-token-42", Some("codex"), 10, 0)?;
        assert_eq!(search.total, 1);
        assert_eq!(search.hits[0].matched_field, "message");
        assert!(search.hits[0].snippet.contains("alpha-token-42"));

        let title_search = store.search_sessions("Importer", None, 10, 0)?;
        assert_eq!(title_search.total, 1);
        assert_eq!(title_search.hits[0].matched_field, "title");
        Ok(())
    }

    #[test]
    fn redaction_removes_search_and_wakeup_signal() -> Result<()> {
        let dir = tempdir()?;
        let store = ConversationStore::new(dir.path());
        let imported = store.import_session(import_fixture())?;

        let before = store.search_sessions("wake-up", None, 10, 0)?;
        assert_eq!(before.total, 1);

        let result = store
            .redact_session(&imported.session_id)?
            .expect("redaction result should exist");
        assert!(result.redacted);

        let session = store
            .read_session(&imported.session_id)?
            .expect("redacted session should still exist");
        assert_eq!(session.title.as_deref(), Some(REDACTION_PLACEHOLDER));
        assert!(!session.raw_messages_stored);
        assert_eq!(session.messages.len(), session.message_count as usize);
        assert!(session
            .messages
            .iter()
            .all(|message| message.content == REDACTION_PLACEHOLDER));

        let after = store.search_sessions("wake-up", None, 10, 0)?;
        assert_eq!(after.total, 0);

        let wakeup = store.build_wakeup_bundle(Some("codex"), Some("wake-up"), 3, 2)?;
        assert!(wakeup.episodic_summaries.is_empty());
        assert!(wakeup.transcript_snippets.is_empty());
        Ok(())
    }

    #[test]
    fn writes_and_reads_diary_entries() -> Result<()> {
        let dir = tempdir()?;
        let store = ConversationStore::new(dir.path());
        let first = store.write_diary_entry(
            Some("codex"),
            "note",
            "Remember to summarize session close state.",
            None,
            json!({"source":"manual"}),
        )?;
        let second = store.write_diary_entry(
            Some("reviewer"),
            "review",
            "Flag missing hook coverage.",
            Some("session-2"),
            json!({}),
        )?;

        let all = store.read_diary_entries(None, 10, 0)?;
        assert_eq!(all.total, 2);
        assert_eq!(all.entries[0].entry_id, second.entry_id);
        assert_eq!(all.entries[1].entry_id, first.entry_id);

        let filtered = store.read_diary_entries(Some("codex"), 10, 0)?;
        assert_eq!(filtered.total, 1);
        assert_eq!(filtered.entries[0].entry_id, first.entry_id);
        Ok(())
    }

    #[test]
    fn enqueues_and_marks_hook_events() -> Result<()> {
        let dir = tempdir()?;
        let store = ConversationStore::new(dir.path());
        let queued = store.enqueue_hook_event(&ConversationHookPayload {
            action: ConversationHookAction::SessionCloseSummarization,
            source: Some("codex".to_string()),
            source_session_id: Some("session-1".to_string()),
            title: Some("Hook queue".to_string()),
            agent_id: Some("codex".to_string()),
            transport: Some("hook".to_string()),
            started_at_ms: Some(10),
            ended_at_ms: Some(20),
            format: Some("plain_text".to_string()),
            messages: None,
            transcript_text: Some("user: hi".to_string()),
            summary_text: None,
            metadata: json!({"hook":true}),
        })?;
        let mut processed = queued.clone();
        processed.status = "processed".to_string();
        processed.processed_at_ms = Some(30);
        processed.session_id = Some("session-local".to_string());
        store.mark_hook_event_processed(&queued.event_id, &processed)?;

        let conn = store.open_connection()?;
        let row = conn.query_row(
            "SELECT status, result_json FROM conversation_hook_events WHERE id = ?1",
            rusqlite::params![queued.event_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
        )?;
        assert_eq!(row.0, "processed");
        assert!(row.1.unwrap_or_default().contains("session-local"));
        Ok(())
    }

    #[test]
    fn prunes_retention_with_dry_run_then_apply() -> Result<()> {
        let dir = tempdir()?;
        let store = ConversationStore::new(dir.path());
        let manual = store.import_session(import_fixture())?;
        let queued = store.enqueue_hook_event(&ConversationHookPayload {
            action: ConversationHookAction::SessionCloseSummarization,
            source: Some("codex".to_string()),
            source_session_id: Some(manual.session_id.clone()),
            title: Some("Retention".to_string()),
            agent_id: Some("codex".to_string()),
            transport: Some("hook".to_string()),
            started_at_ms: Some(10),
            ended_at_ms: Some(20),
            format: Some("plain_text".to_string()),
            messages: None,
            transcript_text: Some("user: hi".to_string()),
            summary_text: None,
            metadata: json!({}),
        })?;
        store.write_diary_entry(
            Some("codex"),
            "note",
            "trim me",
            Some(&manual.session_id),
            json!({}),
        )?;

        let conn = store.open_connection()?;
        conn.execute(
            "UPDATE conversation_sessions SET imported_at_ms = 1 WHERE id = ?1",
            params![manual.session_id],
        )?;
        conn.execute(
            "UPDATE conversation_diary_entries SET created_at_ms = 1",
            [],
        )?;
        conn.execute(
            "UPDATE conversation_hook_events SET queued_at_ms = 1 WHERE id = ?1",
            params![queued.event_id],
        )?;
        drop(conn);

        let dry_run = store.prune_retention(
            &ConversationRetentionPolicy {
                manual_retention_days: 1,
                auto_capture_retention_days: 1,
                diary_retention_days: 1,
                hook_event_retention_days: 1,
                working_memory_retention_days: 1,
                episodic_rollup_retention_days: 30,
            },
            false,
        )?;
        assert!(!dry_run.applied);
        assert_eq!(dry_run.deleted_manual_sessions, 1);
        assert_eq!(dry_run.deleted_diary_entries, 1);
        assert_eq!(dry_run.deleted_hook_events, 1);
        assert!(store.read_session(&manual.session_id)?.is_some());

        let applied = store.prune_retention(
            &ConversationRetentionPolicy {
                manual_retention_days: 1,
                auto_capture_retention_days: 1,
                diary_retention_days: 1,
                hook_event_retention_days: 1,
                working_memory_retention_days: 1,
                episodic_rollup_retention_days: 30,
            },
            true,
        )?;
        assert!(applied.applied);
        assert_eq!(applied.deleted_manual_sessions, 1);
        assert!(store.read_session(&manual.session_id)?.is_none());
        Ok(())
    }

    #[test]
    fn namespace_sweeps_create_rollups_and_remove_expired_sessions() -> Result<()> {
        let dir = tempdir()?;
        let store = ConversationStore::for_namespace(dir.path(), "shared-team");
        let imported = store.import_session(import_fixture())?;

        let conn = store.open_connection()?;
        conn.execute(
            "UPDATE conversation_sessions SET imported_at_ms = 1 WHERE id = ?1",
            params![imported.session_id],
        )?;
        drop(conn);

        let result = crate::conversations::sweep_conversation_namespaces(
            dir.path(),
            &ConversationRetentionPolicy {
                manual_retention_days: 1,
                auto_capture_retention_days: 1,
                diary_retention_days: 30,
                hook_event_retention_days: 30,
                working_memory_retention_days: 1,
                episodic_rollup_retention_days: 30,
            },
            true,
            true,
        )?;

        assert_eq!(result.namespace_count, 1);
        assert_eq!(result.pruned_namespace_count, 1);
        assert_eq!(result.prune_result.deleted_manual_sessions, 1);
        assert_eq!(result.prune_result.created_rollups, 1);
        assert!(store.read_session(&imported.session_id)?.is_none());

        let wakeup = store.build_wakeup_bundle(Some("codex"), None, 5, 0)?;
        assert_eq!(wakeup.episodic_summaries.len(), 1);
        assert!(wakeup.episodic_summaries[0]
            .summary
            .contains("Archived 1 conversation session"));
        Ok(())
    }
}
