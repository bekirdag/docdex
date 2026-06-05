use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64Engine;
use base64::Engine as _;
use chrono::DateTime;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracing::warn;
use uuid::Uuid;
use walkdir::WalkDir;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

mod capture;
mod claims;
mod clone;
mod db;
mod digest;
mod export;
mod feedback;
mod generated_skills;
mod governance;
mod health;
mod migrations;
mod mind_map;
mod operator_events;
mod retention;
mod routines;
mod temporal;
mod transcript_scan;
mod types;
mod util;

pub use digest::{
    extract_digest_output, is_supported_client_transcript_source,
    process_pending_with_local_agents, project_safe_preferences_to_profile,
    should_capture_external_source, status_payload_with_config,
};
pub use types::*;

use capture::*;
use claims::*;
use clone::*;
use db::*;
use digest::load_digest_failure_breakdown;
#[cfg(test)]
use digest::{build_digest_context, heuristic_digest_output, should_use_heuristic_digest};
use feedback::*;
use governance::*;
use health::*;
use migrations::*;
use mind_map::*;
use retention::*;
use routines::*;
use temporal::*;
use transcript_scan::*;
use util::*;

use export::{
    export_row_ids, export_table_json, export_table_json_where_any_in,
    export_table_json_where_like_any, payload_array_len,
};

use crate::config::{LlmConfig, MemoryPersonalPreferencesConfig};
use crate::conversations::{
    normalize_import_request, ConversationImport, ConversationImportEnvelope,
    ConversationImportFormat, ConversationMessage,
};
use crate::llm::delegation::{
    build_local_target_candidates_with_config, run_delegation_flow_with_failure_history,
    DelegationFailureHistoryContext, DelegationMode, LocalTarget, TaskType,
};
use crate::llm::local_library::{
    load_local_library, local_agent_is_cloud, refresh_local_library_if_stale,
};
use crate::profiles::{PreferenceCategory, ProfileEmbedder, ProfileManager};
use crate::state_layout::ensure_state_dir_secure;

struct ProcessingCaptureGuard<'a> {
    store: &'a PersonalPreferencesStore,
    capture_id: String,
    digest_job_id: String,
    active: bool,
}

impl<'a> ProcessingCaptureGuard<'a> {
    fn new(store: &'a PersonalPreferencesStore, capture_id: String, digest_job_id: String) -> Self {
        Self {
            store,
            capture_id,
            digest_job_id,
            active: true,
        }
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for ProcessingCaptureGuard<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Err(err) = self.store.mark_capture_status(
            &self.capture_id,
            DIGEST_STATUS_PENDING,
            Some("processing_interrupted"),
        ) {
            warn!(
                target: "docdexd",
                capture_id = %self.capture_id,
                error = ?err,
                "failed to reset interrupted personal-preferences capture"
            );
        }
        if let Err(err) = self.store.complete_digest_job(
            &self.digest_job_id,
            DIGEST_STATUS_PENDING,
            Some("processing_interrupted"),
            json!({ "interrupted": true }),
        ) {
            warn!(
                target: "docdexd",
                capture_id = %self.capture_id,
                digest_job_id = %self.digest_job_id,
                error = ?err,
                "failed to mark interrupted personal-preferences digest job"
            );
        }
    }
}

#[derive(Clone)]
pub struct PersonalPreferencesStore {
    root_dir: PathBuf,
    archive_dir: PathBuf,
    queue_dir: PathBuf,
    exports_dir: PathBuf,
    redactions_dir: PathBuf,
    locks_dir: PathBuf,
    db_path: PathBuf,
}

impl PersonalPreferencesStore {
    pub fn new(root_dir: &Path) -> Result<Self> {
        ensure_state_dir_secure(root_dir)?;
        let archive_dir = root_dir.join("archive");
        let queue_dir = root_dir.join("queue");
        let exports_dir = root_dir.join("exports");
        let redactions_dir = root_dir.join("redactions");
        let locks_dir = root_dir.join("locks");
        ensure_state_dir_secure(&archive_dir)?;
        ensure_state_dir_secure(&queue_dir)?;
        ensure_state_dir_secure(&exports_dir)?;
        ensure_state_dir_secure(&redactions_dir)?;
        ensure_state_dir_secure(&locks_dir)?;
        let db_path = root_dir.join(DB_FILE);
        init_db(&db_path)?;
        Ok(Self {
            root_dir: root_dir.to_path_buf(),
            archive_dir,
            queue_dir,
            exports_dir,
            redactions_dir,
            locks_dir,
            db_path,
        })
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn archive_dir(&self) -> &Path {
        &self.archive_dir
    }

    pub fn exports_dir(&self) -> &Path {
        &self.exports_dir
    }

    pub fn locks_dir(&self) -> &Path {
        &self.locks_dir
    }

    pub fn capture_conversation(
        &self,
        request: PersonalPreferencesCaptureRequest,
        queue_for_processing: bool,
        archive_raw_conversations: bool,
    ) -> Result<PersonalPreferencesCaptureRecord> {
        self.capture_conversation_with_options(
            request,
            PersonalPreferencesCaptureOptions {
                queue_for_processing,
                archive_raw_conversations,
                ..PersonalPreferencesCaptureOptions::default()
            },
        )
    }

    pub fn capture_conversation_with_options(
        &self,
        request: PersonalPreferencesCaptureRequest,
        options: PersonalPreferencesCaptureOptions,
    ) -> Result<PersonalPreferencesCaptureRecord> {
        let mut conn = open_db(&self.db_path)?;
        let tx = conn.transaction()?;
        let now = now_ms();
        let capture_id = Uuid::new_v4().to_string();
        let cipher = resolve_content_cipher(options.content_encryption_key_env.as_deref());
        let prepared_request = prepare_capture_request_for_storage(
            request,
            options.secret_scrubber_enabled,
            cipher.as_ref(),
        );
        let transcript_text = normalize_capture_text(&prepared_request);
        let digest_status = if options.queue_for_processing {
            DIGEST_STATUS_PENDING
        } else {
            DIGEST_STATUS_CAPTURED
        };
        let archive_path = if options.archive_raw_conversations {
            Some(self.write_archive_envelope(
                &capture_id,
                now,
                &prepared_request,
                cipher.as_ref(),
            )?)
        } else {
            None
        };
        tx.execute(
            "INSERT INTO captured_conversations(
                id, source, source_session_id, capture_kind, title, agent_id, transport,
                repo_id, repo_root, scope_id, scope_label, started_at_ms, ended_at_ms,
                created_at_ms, updated_at_ms, digest_status, transcript_text, metadata_json,
                archive_path, raw_message_count, archive_redacted_at_ms, last_digest_error
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, NULL, NULL)",
            params![
                capture_id,
                prepared_request.source,
                prepared_request.source_session_id,
                prepared_request.capture_kind,
                prepared_request.title,
                prepared_request.agent_id,
                prepared_request.transport,
                prepared_request.repo_id,
                prepared_request.repo_root,
                prepared_request.scope_id,
                prepared_request.scope_label,
                prepared_request.started_at_ms,
                prepared_request.ended_at_ms,
                now,
                now,
                digest_status,
                protect_text_for_storage(&transcript_text, cipher.as_ref()),
                serde_json::to_string(&prepared_request.metadata)?,
                archive_path.clone().map(|value| value.display().to_string()),
                prepared_request.messages.len() as i64,
            ],
        )?;
        upsert_source_and_session_lineage(&tx, &capture_id, &prepared_request, digest_status, now)?;
        for (ordinal, message) in prepared_request.messages.iter().enumerate() {
            let message_id = Uuid::new_v4().to_string();
            let protected_content =
                protect_text_for_storage(message.content.trim(), cipher.as_ref());
            let metadata_json = serde_json::to_string(&message.metadata)?;
            tx.execute(
                "INSERT INTO captured_messages(
                    id, capture_id, ordinal, role, content, created_at_ms, metadata_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    message_id,
                    capture_id,
                    ordinal as i64,
                    normalize_text(&message.role),
                    protected_content,
                    message.created_at_ms,
                    metadata_json,
                ],
            )?;
            tx.execute(
                "INSERT INTO pp_messages(
                    id, capture_id, message_id, ordinal, role, content, created_at_ms, metadata_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    format!("ppmsg_{message_id}"),
                    capture_id,
                    message_id,
                    ordinal as i64,
                    normalize_text(&message.role),
                    protected_content,
                    message.created_at_ms,
                    metadata_json,
                ],
            )?;
        }
        tx.commit()?;
        self.sync_queue_marker(&capture_id, digest_status)?;
        self.read_capture(&capture_id)?
            .ok_or_else(|| anyhow!("captured conversation missing after insert"))
    }

    pub fn list_captures(
        &self,
        status: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<PersonalPreferencesCaptureList> {
        let conn = open_db(&self.db_path)?;
        let status = status
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let total = if let Some(ref status) = status {
            count_query_with_param(
                &conn,
                "SELECT COUNT(*) FROM captured_conversations WHERE digest_status = ?1",
                params![status],
            )?
        } else {
            count_query(&conn, "SELECT COUNT(*) FROM captured_conversations")?
        };
        let sql = if status.is_some() {
            "SELECT id, source, source_session_id, capture_kind, title, agent_id, transport,
                    repo_id, repo_root, scope_id, scope_label, started_at_ms, ended_at_ms,
                    created_at_ms, updated_at_ms, digest_status, transcript_text, metadata_json,
                    archive_path, raw_message_count, archive_redacted_at_ms, last_digest_error
             FROM captured_conversations
             WHERE digest_status = ?1
             ORDER BY created_at_ms DESC
             LIMIT ?2 OFFSET ?3"
        } else {
            "SELECT id, source, source_session_id, capture_kind, title, agent_id, transport,
                    repo_id, repo_root, scope_id, scope_label, started_at_ms, ended_at_ms,
                    created_at_ms, updated_at_ms, digest_status, transcript_text, metadata_json,
                    archive_path, raw_message_count, archive_redacted_at_ms, last_digest_error
             FROM captured_conversations
             ORDER BY created_at_ms DESC
             LIMIT ?1 OFFSET ?2"
        };
        let mut stmt = conn.prepare(sql)?;
        let mut rows = if let Some(ref status) = status {
            stmt.query(params![status, limit.max(1) as i64, offset as i64])?
        } else {
            stmt.query(params![limit.max(1) as i64, offset as i64])?
        };
        let mut items = Vec::new();
        while let Some(row) = rows.next()? {
            let mut capture = row_to_capture(row)?;
            hydrate_capture_content(&mut capture);
            items.push(capture);
        }
        Ok(PersonalPreferencesCaptureList { total, items })
    }

    pub fn read_capture(
        &self,
        capture_id: &str,
    ) -> Result<Option<PersonalPreferencesCaptureRecord>> {
        let conn = open_db(&self.db_path)?;
        let mut stmt = conn.prepare(
            "SELECT id, source, source_session_id, capture_kind, title, agent_id, transport,
                    repo_id, repo_root, scope_id, scope_label, started_at_ms, ended_at_ms,
                    created_at_ms, updated_at_ms, digest_status, transcript_text, metadata_json,
                    archive_path, raw_message_count, archive_redacted_at_ms, last_digest_error
             FROM captured_conversations
             WHERE id = ?1",
        )?;
        let capture = stmt
            .query_row(params![capture_id], row_to_capture)
            .optional()?;
        let Some(mut capture) = capture else {
            return Ok(None);
        };
        hydrate_capture_content(&mut capture);
        capture.messages = self.messages_for_capture(capture_id, &capture.metadata)?;
        if capture.messages.is_empty() {
            if let Some(path) = capture.archive_path.as_deref() {
                if let Ok(envelope) = self.read_archive_envelope(Path::new(path)) {
                    capture.messages = envelope.request.messages;
                    if capture.transcript_text.trim().is_empty() {
                        capture.transcript_text =
                            envelope.request.transcript_text.unwrap_or_default();
                    }
                }
            }
        }
        Ok(Some(capture))
    }

    pub fn status(&self) -> Result<PersonalPreferenceStatus> {
        let conn = open_db(&self.db_path)?;
        let captures_total = count_query(&conn, "SELECT COUNT(*) FROM captured_conversations")?;
        let pending_captures = count_query(
            &conn,
            "SELECT COUNT(*) FROM captured_conversations WHERE digest_status = 'pending'",
        )?;
        let processing_captures = count_query(
            &conn,
            "SELECT COUNT(*) FROM captured_conversations WHERE digest_status = 'processing'",
        )?;
        let completed_captures = count_query(
            &conn,
            "SELECT COUNT(*) FROM captured_conversations WHERE digest_status = 'completed'",
        )?;
        let failed_captures = count_query(
            &conn,
            "SELECT COUNT(*) FROM captured_conversations WHERE digest_status = 'failed'",
        )?;
        let derived_records_total = count_query(&conn, "SELECT COUNT(*) FROM derived_records")?;
        let sources_total = count_query(&conn, "SELECT COUNT(*) FROM pp_sources")?;
        let digest_runs_total = count_query(&conn, "SELECT COUNT(*) FROM pp_digest_runs")?;
        let snapshot_summaries_total =
            count_query(&conn, "SELECT COUNT(*) FROM pp_snapshot_summaries")?;
        let claims_total = count_query(&conn, "SELECT COUNT(*) FROM pp_claims")?;
        let feedback_events_total = count_query(&conn, "SELECT COUNT(*) FROM pp_feedback_events")?;
        let identity_snapshots_total =
            count_query(&conn, "SELECT COUNT(*) FROM pp_identity_snapshots")?;
        let decision_patterns_total =
            count_query(&conn, "SELECT COUNT(*) FROM pp_decision_patterns")?;
        let style_signals_total = count_query(&conn, "SELECT COUNT(*) FROM pp_style_signals")?;
        let clone_profiles_total = count_query(&conn, "SELECT COUNT(*) FROM pp_clone_profiles")?;
        let clone_context_packs_total =
            count_query(&conn, "SELECT COUNT(*) FROM pp_clone_context_packs")?;
        let clone_evaluations_total =
            count_query(&conn, "SELECT COUNT(*) FROM pp_clone_evaluations")?;
        let claim_evidence_total = count_query(&conn, "SELECT COUNT(*) FROM pp_claim_evidence")?;
        let claim_links_total = count_query(&conn, "SELECT COUNT(*) FROM pp_claim_links")?;
        let project_timelines_total =
            count_query(&conn, "SELECT COUNT(*) FROM pp_project_timelines")?;
        let goal_graph_total = count_query(&conn, "SELECT COUNT(*) FROM pp_goal_graph")?;
        let operator_routines_total =
            count_query(&conn, "SELECT COUNT(*) FROM pp_operator_routines")?;
        let operator_events_total = count_query(&conn, "SELECT COUNT(*) FROM pp_operator_events")?;
        let override_rules_total = count_query(&conn, "SELECT COUNT(*) FROM pp_override_rules")?;
        let redaction_spans_total = count_query(&conn, "SELECT COUNT(*) FROM pp_redaction_spans")?;
        let retention_policies_total =
            count_query(&conn, "SELECT COUNT(*) FROM pp_retention_policies")?;
        let profile_projected_records_total = count_query(
            &conn,
            "SELECT COUNT(*) FROM derived_records WHERE projected_to_profile_at_ms IS NOT NULL",
        )?;
        let noisy_claims_total = count_query(
            &conn,
            "SELECT COUNT(*) FROM pp_claims
             WHERE truth_status IN ('rejected', 'superseded', 'expired')
                OR contradicted_by_claim_id IS NOT NULL
                OR supersedes_claim_id IS NOT NULL",
        )?;
        let last_capture_at_ms = conn
            .query_row(
                "SELECT MAX(created_at_ms) FROM captured_conversations",
                [],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?
            .flatten();
        let last_processed_at_ms = conn
            .query_row(
                "SELECT MAX(updated_at_ms) FROM captured_conversations WHERE digest_status = 'completed'",
                [],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?
            .flatten();
        let last_scan_capture_at_ms = conn
            .query_row(
                "SELECT MAX(created_at_ms) FROM pp_sessions WHERE capture_kind = 'client_transcript_scan'",
                [],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?
            .flatten();
        let last_scan_at_ms =
            read_meta_i64(&conn, LAST_TRANSCRIPT_SCAN_META_KEY)?.or(last_scan_capture_at_ms);
        let digest_failure_breakdown = load_digest_failure_breakdown(&conn)?;
        let mut status = PersonalPreferenceStatus {
            storage_root: self.root_dir.display().to_string(),
            captures_total,
            pending_captures,
            processing_captures,
            completed_captures,
            failed_captures,
            derived_records_total,
            sources_total,
            digest_runs_total,
            snapshot_summaries_total,
            claims_total,
            feedback_events_total,
            identity_snapshots_total,
            decision_patterns_total,
            style_signals_total,
            clone_profiles_total,
            clone_context_packs_total,
            clone_evaluations_total,
            claim_evidence_total,
            claim_links_total,
            project_timelines_total,
            goal_graph_total,
            operator_routines_total,
            operator_events_total,
            override_rules_total,
            redaction_spans_total,
            retention_policies_total,
            archive_files_total: count_files(&self.archive_dir)?,
            export_files_total: count_files(&self.exports_dir)?,
            last_capture_at_ms,
            last_processed_at_ms,
            last_scan_at_ms,
            digest_failure_breakdown,
            clone_readiness: PersonalPreferenceCloneReadiness::default(),
        };
        status.clone_readiness =
            build_clone_readiness(&status, profile_projected_records_total, noisy_claims_total);
        Ok(status)
    }

    pub fn list_categories(&self) -> Result<Vec<PersonalPreferenceCategory>> {
        let conn = open_db(&self.db_path)?;
        load_category_rows(&conn)
    }

    pub fn scan_supported_client_transcripts(
        &self,
        config: &MemoryPersonalPreferencesConfig,
        limit: Option<usize>,
    ) -> Result<PersonalPreferencesTranscriptScanSummary> {
        if !config.capture_enabled {
            return Ok(PersonalPreferencesTranscriptScanSummary::default());
        }
        let terminal_capture_enabled = config.capture_supported_client_transcripts
            || self.has_enabled_ai_terminal_capture_integrations()?;
        if !terminal_capture_enabled {
            return Ok(PersonalPreferencesTranscriptScanSummary::default());
        }
        let limit = limit.unwrap_or(DEFAULT_TRANSCRIPT_SCAN_LIMIT).clamp(1, 256);
        let candidates = collect_client_transcript_candidates(config, limit.saturating_mul(6))?;
        let mut summary = PersonalPreferencesTranscriptScanSummary::default();
        let mut per_source = BTreeMap::<String, PersonalPreferencesTranscriptSourceSummary>::new();
        let mut seen_paths = HashSet::<PathBuf>::new();
        let mut synced_terminals = BTreeSet::<String>::new();
        let capture_options = PersonalPreferencesCaptureOptions {
            queue_for_processing: config.digest_enabled,
            archive_raw_conversations: config.archive_raw_conversations,
            secret_scrubber_enabled: config.transcript_secret_scrubber_enabled,
            content_encryption_key_env: config.content_encryption_key_env.clone(),
        };
        for candidate in candidates {
            let source_key = candidate.source.clone();
            let source_summary = per_source.entry(source_key.clone()).or_insert_with(|| {
                PersonalPreferencesTranscriptSourceSummary {
                    source: source_key.clone(),
                    ..PersonalPreferencesTranscriptSourceSummary::default()
                }
            });
            if seen_paths.insert(candidate.path.clone()) {
                summary.scanned_files += 1;
                source_summary.scanned_files += 1;
            }
            let imports = match load_transcript_candidate_imports(&candidate) {
                Ok(imports) => imports,
                Err(_) => {
                    summary.parse_errors += 1;
                    source_summary.parse_errors += 1;
                    continue;
                }
            };
            for import in imports {
                if summary.sessions_detected >= limit {
                    break;
                }
                summary.sessions_detected += 1;
                source_summary.sessions_detected += 1;
                let request = capture_request_from_import(&candidate, import);
                let external_ref = external_ref_for_capture_request(&request);
                if let Some(ref value) = external_ref {
                    if self.has_external_session_ref(value)? {
                        summary.skipped_existing += 1;
                        source_summary.skipped_existing += 1;
                        continue;
                    }
                }
                let event_summary = normalize_capture_text(&request);
                let terminal = request.source.clone();
                let source_session_id = request.source_session_id.clone();
                let repo_scope = request.repo_root.clone();
                let metadata = json!({
                    "client_transcript_path": request
                        .metadata
                        .get("client_transcript_path")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "client_transcript_source": request
                        .metadata
                        .get("client_transcript_source")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "client_transcript_adapter": request
                        .metadata
                        .get("client_transcript_adapter")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "client_transcript_format": request
                        .metadata
                        .get("client_transcript_format")
                        .cloned()
                        .unwrap_or(Value::Null),
                });
                let capture =
                    self.capture_conversation_with_options(request, capture_options.clone())?;
                if self
                    .record_scanned_ai_terminal_capture_event(
                        &terminal,
                        source_session_id,
                        repo_scope,
                        &event_summary,
                        &capture.id,
                        metadata,
                    )?
                    .is_some()
                {
                    synced_terminals.insert(terminal);
                }
                summary.captures_created += 1;
                source_summary.captures_created += 1;
            }
            if summary.sessions_detected >= limit {
                break;
            }
        }
        summary.sources = per_source.into_values().collect();
        let scan_completed_at_ms = now_ms();
        write_meta_i64(
            &self.db_path,
            LAST_TRANSCRIPT_SCAN_META_KEY,
            scan_completed_at_ms,
        )?;
        summary.last_scan_at_ms = Some(scan_completed_at_ms);
        if !synced_terminals.is_empty() {
            let _ = self.sync_generated_skills(PersonalPreferenceGeneratedSkillsSyncOptions {
                min_confidence: None,
                min_support_count: None,
                include_sensitive: Some(false),
                install: Some(true),
                terminals: synced_terminals.into_iter().collect(),
            });
        }
        Ok(summary)
    }

    pub fn list_review_records(
        &self,
        status: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<PersonalPreferencesReviewQueue> {
        let conn = open_db(&self.db_path)?;
        let mut records = load_all_records(&conn)?;
        let normalized_status = status
            .and_then(normalize_review_status)
            .map(ToOwned::to_owned);
        if let Some(status) = normalized_status.as_deref() {
            records.retain(|record| record.review_status == status);
        }
        records.sort_by(|left, right| {
            right.updated_at_ms.cmp(&left.updated_at_ms).then_with(|| {
                right
                    .confidence
                    .partial_cmp(&left.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        });
        let total = records.len();
        let items = records
            .into_iter()
            .skip(offset)
            .take(limit.max(1))
            .collect::<Vec<_>>();
        Ok(PersonalPreferencesReviewQueue { total, items })
    }

    pub fn list_reviews_for_record(
        &self,
        record_id: &str,
        limit: usize,
        offset: usize,
    ) -> Result<PersonalPreferencesReviewList> {
        let record_id = record_id.trim();
        if record_id.is_empty() {
            return Err(anyhow!("record_id must not be empty"));
        }
        let conn = open_db(&self.db_path)?;
        let total = count_query_with_param(
            &conn,
            "SELECT COUNT(*) FROM pp_reviews WHERE record_id = ?1",
            params![record_id],
        )?;
        let mut stmt = conn.prepare(
            "SELECT id, record_id, verdict, notes, created_at_ms
             FROM pp_reviews
             WHERE record_id = ?1
             ORDER BY created_at_ms DESC
             LIMIT ?2 OFFSET ?3",
        )?;
        let mut rows = stmt.query(params![record_id, limit.max(1) as i64, offset as i64])?;
        let mut items = Vec::new();
        while let Some(row) = rows.next()? {
            items.push(PersonalPreferenceReview {
                id: row.get(0)?,
                record_id: row.get(1)?,
                verdict: row.get(2)?,
                notes: row.get(3)?,
                created_at_ms: row.get(4)?,
            });
        }
        Ok(PersonalPreferencesReviewList { total, items })
    }

    pub fn review_record(
        &self,
        record_id: &str,
        verdict: &str,
        notes: Option<&str>,
    ) -> Result<PersonalPreferencesReviewSummary> {
        let record_id = record_id.trim();
        if record_id.is_empty() {
            return Err(anyhow!("record_id must not be empty"));
        }
        let verdict = normalize_review_status(verdict)
            .ok_or_else(|| anyhow!("verdict must be approved, pending_review, or rejected"))?;
        let note_text = notes
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let mut conn = open_db(&self.db_path)?;
        let tx = conn.transaction()?;
        let now = now_ms();
        let updated = tx.execute(
            "UPDATE derived_records
             SET review_status = ?2, review_updated_at_ms = ?3, updated_at_ms = ?3
             WHERE id = ?1",
            params![record_id, verdict, now],
        )?;
        if updated == 0 {
            return Err(anyhow!("record not found"));
        }
        sync_materialized_record_status(&tx, record_id, verdict, now)?;
        let review_id = Uuid::new_v4().to_string();
        tx.execute(
            "INSERT INTO pp_reviews(id, record_id, verdict, notes, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![review_id, record_id, verdict, note_text, now],
        )?;
        tx.commit()?;
        Ok(PersonalPreferencesReviewSummary {
            record_id: record_id.to_string(),
            review_status: verdict.to_string(),
            review_id,
        })
    }

    pub fn prune_retention(
        &self,
        raw_retention_days: u32,
        derived_retention_days: u32,
        apply: bool,
    ) -> Result<PersonalPreferencesPruneSummary> {
        let conn = open_db(&self.db_path)?;
        let raw_cutoff = retention_cutoff_ms(raw_retention_days);
        let derived_cutoff = retention_cutoff_ms(derived_retention_days);

        let raw_candidates = if let Some(cutoff_ms) = raw_cutoff {
            let mut stmt = conn.prepare(
                "SELECT id
                 FROM captured_conversations
                 WHERE created_at_ms < ?1
                   AND archive_redacted_at_ms IS NULL
                   AND (raw_message_count > 0 OR trim(transcript_text) != '')",
            )?;
            let mut rows = stmt.query(params![cutoff_ms])?;
            let mut ids = Vec::new();
            while let Some(row) = rows.next()? {
                ids.push(row.get::<_, String>(0)?);
            }
            ids
        } else {
            Vec::new()
        };

        let derived_candidates = if let Some(cutoff_ms) = derived_cutoff {
            count_query_with_param(
                &conn,
                "SELECT COUNT(*) FROM derived_records WHERE updated_at_ms < ?1",
                params![cutoff_ms],
            )?
        } else {
            0
        };
        let claim_candidates = if let Some(cutoff_ms) = derived_cutoff {
            count_query_with_param(
                &conn,
                "SELECT COUNT(*) FROM pp_claims
                 WHERE updated_at_ms < ?1
                   AND (record_id IS NULL
                        OR truth_status IN ('rejected', 'superseded', 'expired'))",
                params![cutoff_ms],
            )?
        } else {
            0
        };
        let snapshot_candidates = if let Some(cutoff_ms) = derived_cutoff {
            count_query_with_param(
                &conn,
                "SELECT COUNT(*) FROM pp_identity_snapshots WHERE created_at_ms < ?1",
                params![cutoff_ms],
            )?
        } else {
            0
        };
        let clone_candidates = if let Some(cutoff_ms) = derived_cutoff {
            count_query_with_param(
                &conn,
                "SELECT COUNT(*) FROM pp_clone_context_packs WHERE created_at_ms < ?1",
                params![cutoff_ms],
            )? + count_query_with_param(
                &conn,
                "SELECT COUNT(*) FROM pp_clone_evaluations WHERE created_at_ms < ?1",
                params![cutoff_ms],
            )?
        } else {
            0
        };
        let export_candidates = if let Some(cutoff_ms) = raw_cutoff {
            count_files_older_than(&self.exports_dir, cutoff_ms)?
        } else {
            0
        };

        let mut raw_redacted = 0usize;
        if apply {
            for capture_id in &raw_candidates {
                let summary = self.redact_capture(capture_id)?;
                if summary.redacted {
                    raw_redacted += 1;
                }
            }
        }

        let mut derived_deleted = 0usize;
        let mut claims_deleted = 0usize;
        let mut snapshots_deleted = 0usize;
        let mut clone_artifacts_deleted = 0usize;
        let mut exports_deleted = 0usize;
        let mut retention_policies_updated = 0usize;
        if apply {
            if let Some(cutoff_ms) = derived_cutoff {
                derived_deleted = conn.execute(
                    "DELETE FROM derived_records WHERE updated_at_ms < ?1",
                    params![cutoff_ms],
                )?;
                claims_deleted = conn.execute(
                    "DELETE FROM pp_claims
                     WHERE updated_at_ms < ?1
                       AND (record_id IS NULL
                            OR truth_status IN ('rejected', 'superseded', 'expired'))",
                    params![cutoff_ms],
                )?;
                snapshots_deleted = conn.execute(
                    "DELETE FROM pp_identity_snapshots WHERE created_at_ms < ?1",
                    params![cutoff_ms],
                )?;
                clone_artifacts_deleted += conn.execute(
                    "DELETE FROM pp_clone_context_packs WHERE created_at_ms < ?1",
                    params![cutoff_ms],
                )?;
                clone_artifacts_deleted += conn.execute(
                    "DELETE FROM pp_clone_evaluations WHERE created_at_ms < ?1",
                    params![cutoff_ms],
                )?;
            }
            if let Some(cutoff_ms) = raw_cutoff {
                exports_deleted = prune_files_older_than(&self.exports_dir, cutoff_ms)?;
            }
            upsert_retention_policy(
                &conn,
                "raw_archive",
                "raw_archive",
                Some(raw_retention_days),
                None,
                None,
                None,
                Some(raw_retention_days),
                &json!({ "updated_from": "prune_retention" }),
            )?;
            upsert_retention_policy(
                &conn,
                "derived_memory",
                "derived_memory",
                None,
                Some(derived_retention_days),
                Some(derived_retention_days),
                Some(derived_retention_days),
                None,
                &json!({ "updated_from": "prune_retention" }),
            )?;
            upsert_retention_policy(
                &conn,
                "clone_artifacts",
                "clone_artifacts",
                None,
                None,
                Some(derived_retention_days),
                Some(derived_retention_days),
                Some(raw_retention_days),
                &json!({ "updated_from": "prune_retention" }),
            )?;
            retention_policies_updated = 3;
        }

        Ok(PersonalPreferencesPruneSummary {
            applied: apply,
            raw_candidates: raw_candidates.len(),
            raw_redacted,
            derived_candidates,
            derived_deleted,
            claim_candidates,
            claims_deleted,
            snapshot_candidates,
            snapshots_deleted,
            clone_artifact_candidates: clone_candidates,
            clone_artifacts_deleted,
            exports_candidates: export_candidates,
            exports_deleted,
            retention_policies_updated,
        })
    }

    pub fn search_records(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<PersonalPreferenceRecord>> {
        self.search_records_with_policy(query, limit, true)
    }

    pub fn search_records_with_policy(
        &self,
        query: &str,
        limit: usize,
        include_sensitive: bool,
    ) -> Result<Vec<PersonalPreferenceRecord>> {
        let conn = open_db(&self.db_path)?;
        let mut records = load_all_records(&conn)?;
        if !include_sensitive {
            records.retain(|record| !is_sensitive_level(&record.sensitivity));
        }
        rank_records(query, &mut records);
        records.truncate(limit.max(1));
        Ok(records)
    }

    pub fn list_claims(
        &self,
        query: PersonalPreferencesClaimsQuery,
    ) -> Result<PersonalPreferenceClaimList> {
        let conn = open_db(&self.db_path)?;
        let mut claims = load_all_claims(&conn)?;
        claims.retain(|claim| !claim_is_forgotten(claim));
        if !query.include_sensitive {
            claims.retain(|claim| !is_sensitive_level(&claim.sensitivity));
        }
        if let Some(status) = query
            .truth_status
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            claims.retain(|claim| claim.truth_status == status);
        }
        if let Some(origin) = query
            .claim_origin
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            claims.retain(|claim| claim.claim_origin == origin);
        }
        let query_text = query.query.unwrap_or_default();
        rank_claims(&query_text, &mut claims);
        let total = claims.len();
        let offset = query.offset.unwrap_or(0);
        let limit = query.limit.unwrap_or(20).clamp(1, 200);
        let items = claims.into_iter().skip(offset).take(limit).collect();
        Ok(PersonalPreferenceClaimList { total, items })
    }

    pub fn read_claim(&self, claim_id: &str) -> Result<Option<PersonalPreferenceClaim>> {
        let conn = open_db(&self.db_path)?;
        load_claim_by_id(&conn, claim_id)
    }

    pub fn forget_claim(
        &self,
        claim_id: &str,
        notes: Option<&str>,
    ) -> Result<PersonalPreferenceClaimForgetSummary> {
        let mut conn = open_db(&self.db_path)?;
        let tx = conn.transaction()?;
        let claim = load_claim_by_id(&tx, claim_id)?
            .ok_or_else(|| anyhow!("personal preference claim not found"))?;
        let now = now_ms();
        let note_text = notes
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let mut claim_metadata = claim.metadata.as_object().cloned().unwrap_or_default();
        claim_metadata.insert("forgotten".to_string(), json!(true));
        claim_metadata.insert("forgotten_at_ms".to_string(), json!(now));
        if let Some(notes) = note_text.as_ref() {
            claim_metadata.insert("forgotten_notes".to_string(), json!(notes));
        }
        tx.execute(
            "UPDATE pp_claims
             SET value = ?2,
                 evidence_summary = ?2,
                 truth_status = ?3,
                 review_status = ?4,
                 valid_to_ms = ?5,
                 updated_at_ms = ?5,
                 metadata_json = ?6
             WHERE id = ?1",
            params![
                claim_id,
                REDACTED_TEXT,
                TRUTH_STATUS_EXPIRED,
                REVIEW_STATUS_REJECTED,
                now,
                serde_json::to_string(&Value::Object(claim_metadata.clone()))?,
            ],
        )?;
        if let Some(record_id) = claim.record_id.as_deref() {
            tx.execute(
                "UPDATE derived_records
                 SET value = ?2,
                     evidence = ?2,
                     review_status = ?3,
                     review_updated_at_ms = ?4,
                     updated_at_ms = ?4,
                     metadata_json = ?5
                 WHERE id = ?1",
                params![
                    record_id,
                    REDACTED_TEXT,
                    REVIEW_STATUS_REJECTED,
                    now,
                    serde_json::to_string(&Value::Object(claim_metadata.clone()))?,
                ],
            )?;
            sync_materialized_record_status(&tx, record_id, REVIEW_STATUS_REJECTED, now)?;
        }
        replace_claim_evidence(
            &tx,
            claim_id,
            claim.capture_id.as_deref(),
            None,
            &Value::Object(claim_metadata.clone()),
            now,
        )?;
        if let Some(capture_id) = claim.capture_id.as_deref() {
            write_redaction_span(
                &tx,
                capture_id,
                Some(claim_id),
                "claim_forget",
                None,
                None,
                REDACTED_TEXT,
                note_text.as_deref().unwrap_or("claim forgotten"),
                &json!({ "claim_id": claim_id }),
                now,
            )?;
        }
        write_claim_version(
            &tx,
            claim_id,
            &json!({
                "action": "forget",
                "notes": note_text.as_deref(),
            }),
            now,
        )?;
        let tombstone_id = format!("tombstone_{}", Uuid::new_v4());
        tx.execute(
            "INSERT INTO pp_tombstones(id, capture_id, action, details_json, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                tombstone_id,
                claim
                    .capture_id
                    .clone()
                    .unwrap_or_else(|| format!("claim:{claim_id}")),
                "forget_claim",
                serde_json::to_string(&json!({
                    "claim_id": claim_id,
                    "record_id": claim.record_id.as_deref(),
                    "notes": note_text.as_deref(),
                }))?,
                now,
            ],
        )?;
        if let Some(routine_key) = operator_routine_key_for_claim(&claim) {
            let routine_id = claim
                .metadata
                .get("routine_id")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or_default()
                .to_string();
            tx.execute(
                "INSERT INTO pp_tombstones(id, capture_id, action, details_json, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    format!("tombstone_{}", Uuid::new_v4()),
                    claim
                        .capture_id
                        .clone()
                        .unwrap_or_else(|| format!("claim:{claim_id}")),
                    "forget_operator_routine",
                    serde_json::to_string(&json!({
                        "claim_id": claim_id,
                        "routine_id": routine_id.as_str(),
                        "routine_key": routine_key.as_str(),
                        "notes": note_text.as_deref(),
                    }))?,
                    now,
                ],
            )?;
            tx.execute(
                "DELETE FROM pp_operator_routine_steps
                 WHERE routine_id IN (
                    SELECT id FROM pp_operator_routines WHERE routine_key = ?1 OR id = ?2
                 )",
                params![routine_key.as_str(), routine_id.as_str()],
            )?;
            tx.execute(
                "DELETE FROM pp_operator_routines WHERE routine_key = ?1 OR id = ?2",
                params![routine_key.as_str(), routine_id.as_str()],
            )?;
        }
        let snapshot_id =
            rebuild_identity_snapshots_tx(&tx, claim.capture_id.as_deref(), "forget")?;
        tx.commit()?;
        Ok(PersonalPreferenceClaimForgetSummary {
            claim_id: claim_id.to_string(),
            forgotten: true,
            affected_record_id: claim.record_id,
            tombstone_id: Some(tombstone_id),
            created_snapshot_id: snapshot_id,
        })
    }

    pub fn list_retention_policies(&self) -> Result<Vec<PersonalPreferenceRetentionPolicy>> {
        let conn = open_db(&self.db_path)?;
        load_retention_policies(&conn)
    }

    pub fn review_claim(
        &self,
        claim_id: &str,
        verdict: &str,
        notes: Option<&str>,
    ) -> Result<PersonalPreferenceClaimReviewSummary> {
        let verdict = normalize_review_status(verdict)
            .ok_or_else(|| anyhow!("verdict must be approved, pending_review, or rejected"))?;
        let mut conn = open_db(&self.db_path)?;
        let tx = conn.transaction()?;
        let claim = load_claim_by_id(&tx, claim_id)?
            .ok_or_else(|| anyhow!("personal preference claim not found"))?;
        let truth_status = match verdict {
            REVIEW_STATUS_APPROVED => {
                if claim.claim_origin == CLAIM_ORIGIN_EXPLICIT_USER_STATEMENT
                    || claim.claim_origin == CLAIM_ORIGIN_EXPLICIT_USER_CORRECTION
                    || claim.claim_origin == CLAIM_ORIGIN_MANUAL_REVIEW_ENTRY
                {
                    TRUTH_STATUS_CONFIRMED
                } else {
                    TRUTH_STATUS_INFERRED
                }
            }
            REVIEW_STATUS_REJECTED => TRUTH_STATUS_REJECTED,
            _ => TRUTH_STATUS_CANDIDATE,
        };
        let now = now_ms();
        tx.execute(
            "UPDATE pp_claims
             SET review_status = ?2, truth_status = ?3, updated_at_ms = ?4
             WHERE id = ?1",
            params![claim_id, verdict, truth_status, now],
        )?;
        write_claim_version(
            &tx,
            claim_id,
            &json!({
                "action": "review",
                "review_status": verdict,
                "truth_status": truth_status,
                "notes": notes,
            }),
            now,
        )?;
        if let Some(record_id) = claim.record_id.as_deref() {
            tx.execute(
                "UPDATE derived_records
                 SET review_status = ?2, review_updated_at_ms = ?3, updated_at_ms = ?3
                 WHERE id = ?1",
                params![record_id, verdict, now],
            )?;
            sync_materialized_record_status(&tx, record_id, verdict, now)?;
            tx.execute(
                "INSERT INTO pp_reviews(id, record_id, verdict, notes, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![Uuid::new_v4().to_string(), record_id, verdict, notes, now],
            )?;
        }
        tx.commit()?;
        Ok(PersonalPreferenceClaimReviewSummary {
            claim_id: claim_id.to_string(),
            review_status: verdict.to_string(),
            truth_status: truth_status.to_string(),
        })
    }

    pub fn override_claim(
        &self,
        claim_id: &str,
        value: &str,
        notes: Option<&str>,
    ) -> Result<PersonalPreferenceFeedbackSummary> {
        self.add_feedback_event(
            FEEDBACK_EVENT_OVERRIDE_PREFERENCE,
            Some(claim_id),
            None,
            None,
            None,
            Some(value),
            notes,
            json!({}),
        )
    }

    pub fn add_feedback_event(
        &self,
        event_type: &str,
        claim_id: Option<&str>,
        capture_id: Option<&str>,
        category: Option<&str>,
        attribute: Option<&str>,
        value: Option<&str>,
        notes: Option<&str>,
        metadata: Value,
    ) -> Result<PersonalPreferenceFeedbackSummary> {
        let event_type = normalize_feedback_event_type(event_type)
            .ok_or_else(|| anyhow!("unsupported feedback event type"))?;
        let mut conn = open_db(&self.db_path)?;
        let tx = conn.transaction()?;
        let now = now_ms();
        let event_id = Uuid::new_v4().to_string();
        let base_claim = match claim_id {
            Some(id) => load_claim_by_id(&tx, id)?,
            None => None,
        };
        tx.execute(
            "INSERT INTO pp_feedback_events(
                id, claim_id, capture_id, event_type, notes, created_at_ms, metadata_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                event_id,
                claim_id,
                capture_id,
                event_type,
                notes,
                now,
                serde_json::to_string(&metadata)?,
            ],
        )?;
        let mut affected_claim_id = claim_id.map(ToOwned::to_owned);
        let mut created_claim_id = None;
        if let Some(claim) = base_claim.as_ref() {
            let (next_confidence, next_truth_status) =
                apply_feedback_to_claim(claim, event_type, value);
            tx.execute(
                "UPDATE pp_claims
                 SET confidence = ?2, truth_status = ?3, updated_at_ms = ?4
                 WHERE id = ?1",
                params![claim.id, next_confidence, next_truth_status, now],
            )?;
            write_claim_version(
                &tx,
                &claim.id,
                &json!({
                    "action": "feedback",
                    "event_type": event_type,
                    "next_confidence": next_confidence,
                    "next_truth_status": next_truth_status,
                    "notes": notes,
                }),
                now,
            )?;
            if matches!(
                event_type,
                FEEDBACK_EVENT_CORRECT_OUTPUT
                    | FEEDBACK_EVENT_REWRITE_OUTPUT
                    | FEEDBACK_EVENT_OVERRIDE_PREFERENCE
            ) {
                if let Some(override_value) = value.map(str::trim).filter(|value| !value.is_empty())
                {
                    let override_claim = create_override_claim_from_claim(
                        &tx,
                        claim,
                        category,
                        attribute,
                        override_value,
                        notes,
                        now,
                    )?;
                    tx.execute(
                        "UPDATE pp_claims
                         SET truth_status = ?2, contradicted_by_claim_id = ?3, updated_at_ms = ?4
                         WHERE id = ?1",
                        params![claim.id, TRUTH_STATUS_SUPERSEDED, override_claim.id, now],
                    )?;
                    created_claim_id = Some(override_claim.id.clone());
                    affected_claim_id = Some(claim.id.clone());
                }
            }
        } else if let Some(new_value) = value.map(str::trim).filter(|value| !value.is_empty()) {
            let claim = create_manual_feedback_claim(
                &tx, event_type, capture_id, category, attribute, new_value, notes, now,
            )?;
            created_claim_id = Some(claim.id.clone());
            affected_claim_id = Some(claim.id);
        }
        let snapshot_id = rebuild_identity_snapshots_tx(&tx, None, "feedback")?;
        tx.commit()?;
        Ok(PersonalPreferenceFeedbackSummary {
            event_id,
            event_type: event_type.to_string(),
            affected_claim_id,
            created_claim_id,
            created_snapshot_id: snapshot_id,
        })
    }

    pub fn list_feedback_events(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<PersonalPreferenceFeedbackEvent>> {
        let conn = open_db(&self.db_path)?;
        load_feedback_events(&conn, limit, offset)
    }

    pub fn list_snapshots(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<PersonalPreferenceSnapshotList> {
        let conn = open_db(&self.db_path)?;
        let snapshots = load_snapshots(&conn, limit, offset)?;
        let total = count_query(&conn, "SELECT COUNT(*) FROM pp_identity_snapshots")?;
        Ok(PersonalPreferenceSnapshotList {
            total,
            items: snapshots,
        })
    }

    pub fn read_snapshot(&self, snapshot_id: &str) -> Result<Option<PersonalPreferenceSnapshot>> {
        let conn = open_db(&self.db_path)?;
        load_snapshot_by_id(&conn, snapshot_id)
    }

    pub fn rebuild_snapshots(&self) -> Result<PersonalPreferenceSnapshotRebuildSummary> {
        let mut conn = open_db(&self.db_path)?;
        let tx = conn.transaction()?;
        let latest_snapshot_id = rebuild_identity_snapshots_tx(&tx, None, "manual_rebuild")?;
        tx.commit()?;
        Ok(PersonalPreferenceSnapshotRebuildSummary {
            created: usize::from(latest_snapshot_id.is_some()),
            latest_snapshot_id,
        })
    }

    pub fn list_operator_routines(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<PersonalPreferenceOperatorRoutineList> {
        let conn = open_db(&self.db_path)?;
        let routines = load_operator_routines(&conn, limit, offset)?;
        let total = count_query(&conn, "SELECT COUNT(*) FROM pp_operator_routines")?;
        Ok(PersonalPreferenceOperatorRoutineList {
            total,
            items: routines,
        })
    }

    pub fn read_operator_routine(
        &self,
        routine_id_or_key: &str,
    ) -> Result<Option<PersonalPreferenceOperatorRoutine>> {
        let conn = open_db(&self.db_path)?;
        load_operator_routine_by_id_or_key(&conn, routine_id_or_key)
    }

    pub fn rebuild_operator_routines(
        &self,
    ) -> Result<PersonalPreferenceOperatorRoutineRebuildSummary> {
        let mut conn = open_db(&self.db_path)?;
        let tx = conn.transaction()?;
        let claims = load_all_claims(&tx)?;
        let rebuilt = rebuild_operator_routines_tx(&tx, None, &claims, now_ms())?;
        let total = count_query(&tx, "SELECT COUNT(*) FROM pp_operator_routines")?;
        let executable_total = count_query(
            &tx,
            "SELECT COUNT(*) FROM pp_operator_routines WHERE autonomy_level IS NOT NULL AND autonomy_level != ''",
        )?;
        let event_supported_steps = count_query(
            &tx,
            "SELECT COUNT(*) FROM pp_operator_routine_steps WHERE event_evidence_ids_json != '[]'",
        )?;
        let drifted_total = count_query(
            &tx,
            "SELECT COUNT(*) FROM pp_operator_routines WHERE drift_status IN ('changed', 'needs_review')",
        )?;
        tx.commit()?;
        Ok(PersonalPreferenceOperatorRoutineRebuildSummary {
            rebuilt,
            total,
            executable_total,
            event_supported_steps,
            drifted_total,
        })
    }

    pub fn explain_operator_routine(
        &self,
        routine_id_or_key: &str,
    ) -> Result<Option<PersonalPreferenceOperatorRoutineExplanation>> {
        let conn = open_db(&self.db_path)?;
        let Some(routine) = load_operator_routine_by_id_or_key(&conn, routine_id_or_key)? else {
            return Ok(None);
        };
        let mut seen_claim_ids = HashSet::new();
        let mut step_evidence = Vec::new();
        for step in &routine.steps {
            let mut claims = Vec::new();
            for claim_id in &step.evidence_claim_ids {
                if let Some(claim) = load_claim_by_id(&conn, claim_id)? {
                    claims.push(claim);
                    seen_claim_ids.insert(claim_id.clone());
                }
            }
            step_evidence.push(PersonalPreferenceOperatorRoutineStepEvidence {
                step_key: step.step_key.clone(),
                claim_ids: step.evidence_claim_ids.clone(),
                claims,
            });
        }
        let notes = vec![
            "Routine confidence is synthesized from supported step coverage, source-claim confidence, and distinct source-claim count.".to_string(),
            "Sensitive, rejected, expired, and forgotten claims are excluded from routine synthesis.".to_string(),
            "Operator event ids on routine steps provide command, git/test/deploy, and artifact sequence evidence.".to_string(),
        ];
        Ok(Some(PersonalPreferenceOperatorRoutineExplanation {
            routine,
            step_evidence,
            evidence_claims_total: seen_claim_ids.len(),
            notes,
        }))
    }

    pub fn compile_mind_map(
        &self,
        query: Option<&str>,
        limit: usize,
        include_sensitive: bool,
    ) -> Result<PersonalPreferenceMindMap> {
        let conn = open_db(&self.db_path)?;
        let query = query
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let limit = limit.clamp(4, 200);
        let mut claims = load_all_claims(&conn)?;
        claims.retain(|claim| {
            !claim_is_forgotten(claim)
                && claim.review_status == REVIEW_STATUS_APPROVED
                && !matches!(
                    claim.truth_status.as_str(),
                    TRUTH_STATUS_REJECTED | TRUTH_STATUS_SUPERSEDED | TRUTH_STATUS_EXPIRED
                )
                && (include_sensitive || !is_sensitive_level(&claim.sensitivity))
        });
        let query_text = query.as_deref().unwrap_or_default();
        claims.sort_by(|left, right| {
            mind_map_claim_score(right, query_text)
                .partial_cmp(&mind_map_claim_score(left, query_text))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| right.updated_at_ms.cmp(&left.updated_at_ms))
        });
        claims.truncate(limit);

        let routines = load_operator_routines(&conn, limit, 0)?;
        let mut nodes = Vec::new();
        let mut node_index = BTreeMap::new();
        let mut edges = Vec::new();
        let mut edge_keys = HashSet::new();

        upsert_mind_map_node(
            &mut nodes,
            &mut node_index,
            "user",
            "operator",
            "Human Operator",
            "The human operator whose preferences, routines, and project behavior are being modeled.",
            1.0,
            None,
            json!({ "source": "root" }),
        );

        for claim in &claims {
            let relation = mind_map_relation_for_claim(claim);
            let claim_node_id = format!("claim:{}", claim.id);
            let claim_summary = render_claim_content(claim);
            upsert_mind_map_node(
                &mut nodes,
                &mut node_index,
                &claim_node_id,
                mind_map_node_type_for_claim(claim),
                mind_map_label_for_claim(claim).as_str(),
                claim_summary.as_str(),
                claim.confidence,
                Some(claim.id.as_str()),
                json!({
                    "category": claim.category.as_str(),
                    "claim_origin": claim.claim_origin.as_str(),
                    "truth_status": claim.truth_status.as_str(),
                    "stability_class": claim.stability_class.as_str(),
                    "sensitivity": claim.sensitivity.as_str(),
                }),
            );
            push_mind_map_edge(
                &mut edges,
                &mut edge_keys,
                "user",
                &claim_node_id,
                relation,
                &format!("Human operator {relation}: {}", claim.value),
                claim.confidence,
                Some(claim.id.as_str()),
                json!({ "source": "claim" }),
            );

            let category_node_id = format!("category:{}", claim.category);
            upsert_mind_map_node(
                &mut nodes,
                &mut node_index,
                &category_node_id,
                "preference_category",
                &claim.category,
                &format!("Claim category {}", claim.category),
                0.65,
                Some(claim.id.as_str()),
                json!({ "category": claim.category.as_str() }),
            );
            push_mind_map_edge(
                &mut edges,
                &mut edge_keys,
                &category_node_id,
                &claim_node_id,
                "contains",
                "Category contains this evidence-backed claim.",
                0.6,
                Some(claim.id.as_str()),
                json!({ "source": "category" }),
            );

            for entity in mind_map_entities_for_claim(claim) {
                upsert_mind_map_node(
                    &mut nodes,
                    &mut node_index,
                    &entity.node_id,
                    &entity.node_type,
                    &entity.label,
                    &entity.summary,
                    entity.weight,
                    Some(claim.id.as_str()),
                    json!({ "source": "entity_heuristic" }),
                );
                push_mind_map_edge(
                    &mut edges,
                    &mut edge_keys,
                    "user",
                    &entity.node_id,
                    &entity.relation,
                    &entity.summary,
                    entity.weight,
                    Some(claim.id.as_str()),
                    json!({ "source": "entity_heuristic" }),
                );
            }
        }

        for routine in &routines {
            if !routine_is_relevant_to_query(routine, query_text) {
                continue;
            }
            let routine_node_id = format!("routine:{}", routine.routine_key);
            upsert_mind_map_node(
                &mut nodes,
                &mut node_index,
                &routine_node_id,
                "operator_routine",
                &routine.title,
                &routine.summary,
                routine.confidence,
                None,
                json!({
                    "routine_id": routine.id.as_str(),
                    "routine_key": routine.routine_key.as_str(),
                    "support_count": routine.support_count,
                    "cross_project_support_count": routine.cross_project_support_count,
                    "event_support_count": routine.event_support_count,
                    "risk_level": routine.risk_level.as_str(),
                    "autonomy_level": routine.autonomy_level.as_str(),
                    "version": routine.version,
                    "drift_status": routine.drift_status.as_str(),
                    "drift_score": routine.drift_score,
                }),
            );
            push_mind_map_edge(
                &mut edges,
                &mut edge_keys,
                "user",
                &routine_node_id,
                "runs_routine",
                &routine.summary,
                routine.confidence,
                None,
                json!({ "source": "operator_routine" }),
            );
            for step in &routine.steps {
                let step_node_id =
                    format!("routine:{}:step:{}", routine.routine_key, step.step_key);
                let first_claim_id = step.evidence_claim_ids.first().map(String::as_str);
                upsert_mind_map_node(
                    &mut nodes,
                    &mut node_index,
                    &step_node_id,
                    "routine_step",
                    &step.title,
                    &step.instruction,
                    step.confidence,
                    first_claim_id,
                    json!({
                        "routine_id": routine.id.as_str(),
                        "routine_key": routine.routine_key.as_str(),
                        "step_key": step.step_key.as_str(),
                        "step_order": step.step_order,
                        "evidence_claim_ids": &step.evidence_claim_ids,
                        "event_evidence_ids": &step.event_evidence_ids,
                        "approval_required": step.approval_required,
                        "success_check": step.success_check.as_str(),
                    }),
                );
                push_mind_map_edge(
                    &mut edges,
                    &mut edge_keys,
                    &routine_node_id,
                    &step_node_id,
                    "has_step",
                    &step.instruction,
                    step.confidence,
                    first_claim_id,
                    json!({ "source": "operator_routine_step" }),
                );
            }
        }

        let notes = vec![
            "Mind-map nodes and edges are compiled from approved non-forgotten claims plus synthesized operator routines.".to_string(),
            "Raw transcripts are not included; provenance is represented by claim ids and routine ids.".to_string(),
            "Query terms affect ordering and routine inclusion but broad operator queries retain workflow/routine evidence.".to_string(),
        ];
        Ok(PersonalPreferenceMindMap {
            query,
            generated_at_ms: now_ms(),
            nodes,
            edges,
            routines,
            notes,
        })
    }

    pub fn compile_operator_playbooks(
        &self,
        min_confidence: f32,
        min_support_count: usize,
        include_sensitive: bool,
    ) -> Result<PersonalPreferenceSkillPlaybookBundle> {
        let conn = open_db(&self.db_path)?;
        let generated_at_ms = now_ms();
        let min_confidence = min_confidence.clamp(0.0, 0.99);
        let min_support_count = min_support_count.max(1);
        let routines = load_operator_routines(&conn, 200, 0)?;
        let mut items = Vec::new();
        let mut skipped = 0usize;
        for routine in routines {
            if routine.confidence < min_confidence || routine.support_count < min_support_count {
                skipped += 1;
                continue;
            }
            let mut evidence_claim_ids = routine
                .steps
                .iter()
                .flat_map(|step| step.evidence_claim_ids.iter().cloned())
                .collect::<Vec<_>>();
            evidence_claim_ids.sort();
            evidence_claim_ids.dedup();
            if !include_sensitive
                && evidence_claim_ids
                    .iter()
                    .filter_map(|claim_id| load_claim_by_id(&conn, claim_id).ok().flatten())
                    .any(|claim| is_sensitive_level(&claim.sensitivity))
            {
                skipped += 1;
                continue;
            }
            let evidence_hash = sha256_hex(&format!(
                "{}:{}:{}",
                routine.routine_key,
                routine.support_count,
                evidence_claim_ids.join(",")
            ));
            let version = format!("{}.{}", routine.version, &evidence_hash[..8]);
            let review_reasons = playbook_review_reasons(&routine);
            let steps = routine
                .steps
                .iter()
                .map(|step| PersonalPreferenceSkillPlaybookStep {
                    step_order: step.step_order,
                    step_key: step.step_key.clone(),
                    title: step.title.clone(),
                    instruction: step.instruction.clone(),
                    required: step.required,
                    tool_hints: step.tool_hints.clone(),
                    expected_artifacts: step.expected_artifacts.clone(),
                    success_check: step.success_check.clone(),
                    failure_recovery: step.failure_recovery.clone(),
                    approval_required: step.approval_required,
                    evidence_claim_ids: step.evidence_claim_ids.clone(),
                    event_evidence_ids: step.event_evidence_ids.clone(),
                    confidence: step.confidence,
                })
                .collect::<Vec<_>>();
            let skill_markdown =
                render_skill_playbook_markdown(&routine, &version, &review_reasons, &steps);
            items.push(PersonalPreferenceSkillPlaybook {
                id: format!("operator_playbook_{}_{}", routine.routine_key, &evidence_hash[..8]),
                routine_id: routine.id.clone(),
                routine_key: routine.routine_key.clone(),
                title: routine.title.clone(),
                description: routine.summary.clone(),
                version,
                format: "SKILL.md".to_string(),
                confidence: routine.confidence,
                support_count: routine.support_count,
                review_required: !review_reasons.is_empty(),
                review_reasons,
                trigger_terms: routine.trigger_terms.clone(),
                steps,
                skill_markdown,
                evidence_claim_ids,
                generated_at_ms,
                metadata: json!({
                    "compiler": "personal_preferences_operator_playbook",
                    "evidence_hash": evidence_hash,
                    "routine_status": routine.status.as_str(),
                    "risk_level": routine.risk_level.as_str(),
                    "autonomy_level": routine.autonomy_level.as_str(),
                    "routine_version": routine.version,
                    "drift_status": routine.drift_status.as_str(),
                    "auto_update_rule": "version changes when supported steps, claim evidence, event evidence, risk, or autonomy changes",
                }),
            });
        }
        Ok(PersonalPreferenceSkillPlaybookBundle {
            generated_at_ms,
            min_confidence,
            min_support_count,
            items,
            skipped,
            notes: vec![
                "Generated playbooks are deterministic SKILL.md-compatible drafts.".to_string(),
                "High-risk production, security, credential, billing, or destructive routines are marked review_required.".to_string(),
                "Versions are evidence-hash based so agents can detect meaningful routine drift.".to_string(),
            ],
        })
    }

    pub fn evaluate_clone_replay(
        &self,
        query: &str,
        options: PersonalPreferencesCloneOptions,
        expected_categories: Vec<String>,
    ) -> Result<PersonalPreferenceCloneReplayEvaluation> {
        let pack = self.build_clone_context_pack(query, options)?;
        let expected_categories = normalize_replay_categories(expected_categories, query);
        let mut expectations = Vec::new();
        let mut matched_categories = Vec::new();
        let mut missing_categories = Vec::new();
        let mut exact_routine_step_matches = 0usize;
        let mut semantic_matches = 0usize;
        for category in &expected_categories {
            let terms = replay_category_terms(category);
            let mut matched_claim_ids = Vec::new();
            let mut matched_routine_keys = Vec::new();
            for item in &pack.items {
                let content = format!("{} {} {}", item.section, item.category, item.content)
                    .to_ascii_lowercase();
                if terms.iter().any(|term| content.contains(term)) {
                    semantic_matches += 1;
                    if let Some(claim_id) = item.claim_id.as_ref() {
                        matched_claim_ids.push(claim_id.clone());
                    }
                    if item.section == "operator_routines" {
                        exact_routine_step_matches += 1;
                    }
                }
            }
            for trace in &pack.trace {
                if trace.section == "operator_routines" {
                    if let Some(routine_key) = trace
                        .claim_id
                        .strip_prefix(OPERATOR_ROUTINE_CLAIM_ID_PREFIX)
                        .map(ToOwned::to_owned)
                    {
                        if !matched_routine_keys.contains(&routine_key)
                            && terms
                                .iter()
                                .any(|term| routine_key.to_ascii_lowercase().contains(term))
                        {
                            matched_routine_keys.push(routine_key);
                        }
                    }
                }
            }
            matched_claim_ids.sort();
            matched_claim_ids.dedup();
            matched_routine_keys.sort();
            matched_routine_keys.dedup();
            let matched = !matched_claim_ids.is_empty() || !matched_routine_keys.is_empty();
            if matched {
                matched_categories.push(category.clone());
            } else {
                missing_categories.push(category.clone());
            }
            expectations.push(PersonalPreferenceCloneReplayExpectation {
                category: category.clone(),
                matched,
                score: if matched { 1.0 } else { 0.0 },
                matched_claim_ids,
                matched_routine_keys,
            });
        }
        let overall_score = if expectations.is_empty() {
            0.0
        } else {
            (expectations.iter().filter(|item| item.matched).count() as f32
                / expectations.len() as f32)
                .clamp(0.0, 1.0)
        };
        let created_at_ms = now_ms();
        let notes = vec![
            "Replay evaluation hides no transcript content; it scores whether the compiled clone pack contains evidence for expected next-step categories.".to_string(),
            "Categories are deterministic workflow buckets: plan, progress_update, repo_inspection, implementation, gap_review, tests, commit, deploy, and backup.".to_string(),
        ];
        let evaluation = PersonalPreferenceCloneReplayEvaluation {
            mode: pack.mode.clone(),
            query: pack.query.clone(),
            overall_score,
            expected_categories,
            matched_categories,
            missing_categories,
            exact_routine_step_matches,
            semantic_matches,
            pack,
            created_at_ms,
            notes,
            expectations,
        };
        let conn = open_db(&self.db_path)?;
        conn.execute(
            "INSERT INTO pp_clone_evaluations(
                id, mode, score, query, notes, created_at_ms, metadata_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                format!("clone_replay_eval_{}", Uuid::new_v4()),
                format!("replay:{}", evaluation.mode),
                evaluation.overall_score,
                evaluation.query.as_str(),
                evaluation.notes.join(" "),
                created_at_ms,
                serde_json::to_string(&json!({
                    "expected_categories": &evaluation.expected_categories,
                    "matched_categories": &evaluation.matched_categories,
                    "missing_categories": &evaluation.missing_categories,
                    "exact_routine_step_matches": evaluation.exact_routine_step_matches,
                    "semantic_matches": evaluation.semantic_matches,
                    "expectations": &evaluation.expectations,
                }))?,
            ],
        )?;
        Ok(evaluation)
    }

    pub fn build_clone_replay_dataset(
        &self,
        ci_subset: bool,
        limit: Option<usize>,
        current_repo_root: Option<String>,
    ) -> Result<PersonalPreferenceCloneReplayDataset> {
        let conn = open_db(&self.db_path)?;
        let generated_at_ms = now_ms();
        let mut routines = load_operator_routines(&conn, 64, 0)?
            .into_iter()
            .filter(|routine| routine.status != "excluded" && !routine.steps.is_empty())
            .collect::<Vec<_>>();
        routines.sort_by(|left, right| {
            let left_priority = usize::from(left.routine_key == "product_development_loop");
            let right_priority = usize::from(right.routine_key == "product_development_loop");
            right_priority
                .cmp(&left_priority)
                .then_with(|| {
                    right
                        .confidence
                        .partial_cmp(&left.confidence)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| right.event_support_count.cmp(&left.event_support_count))
                .then_with(|| right.support_count.cmp(&left.support_count))
                .then_with(|| left.routine_key.cmp(&right.routine_key))
        });

        let mut all_cases = routines
            .iter()
            .enumerate()
            .map(|(index, routine)| {
                clone_replay_dataset_case_from_routine(
                    routine,
                    generated_at_ms,
                    current_repo_root.clone(),
                    index,
                )
            })
            .collect::<Vec<_>>();
        if all_cases.is_empty() {
            all_cases.push(clone_replay_fallback_case(
                generated_at_ms,
                current_repo_root,
            ));
        }

        let ci_subset_total = all_cases.iter().filter(|case| case.ci_subset).count();
        let max_cases = limit.unwrap_or(if ci_subset { 3 } else { 25 }).clamp(1, 64);
        let mut cases = all_cases
            .into_iter()
            .filter(|case| !ci_subset || case.ci_subset)
            .take(max_cases)
            .collect::<Vec<_>>();
        if cases.is_empty() && ci_subset {
            cases.push(clone_replay_fallback_case(generated_at_ms, None));
        }

        Ok(PersonalPreferenceCloneReplayDataset {
            generated_at_ms,
            total: cases.len(),
            ci_subset_total,
            cases,
            notes: vec![
                "Replay cases are generated deterministically from executable operator routines."
                    .to_string(),
                "CI subset cases favor high-support product-development routines and stable fallback coverage."
                    .to_string(),
            ],
        })
    }

    pub fn predict_clone_next_directive(
        &self,
        case: &PersonalPreferenceCloneReplayDatasetCase,
        options: PersonalPreferencesCloneOptions,
    ) -> Result<PersonalPreferenceCloneDirectivePrediction> {
        let directive = self.build_clone_directive(
            &case.query,
            PersonalPreferencesCloneOptions {
                mode: Some(case.mode.clone()),
                allow_sensitive: options.allow_sensitive,
                current_repo_root: case.current_repo_root.clone().or(options.current_repo_root),
                max_records: options.max_records.or(Some(12)),
                budget_tokens: options.budget_tokens.or(Some(1024)),
            },
            Some("clone_replay_harness".to_string()),
            Some("implementation".to_string()),
            None,
            Vec::new(),
            None,
            Some("advisory".to_string()),
        )?;
        let mut predicted_categories = Vec::new();
        let mut predicted_routine_keys = Vec::new();
        let mut predicted_step_keys = Vec::new();
        let mut predicted_required_steps = Vec::new();
        let mut predicted_approval_gates = Vec::new();
        for routine in &directive.selected_routines {
            predicted_routine_keys.push(routine.routine_key.clone());
            clone_replay_push_categories_from_text(
                &mut predicted_categories,
                &format!(
                    "{} {} {} {}",
                    routine.routine_key, routine.title, routine.summary, routine.purpose
                ),
            );
        }
        for step in directive
            .required_steps
            .iter()
            .chain(directive.optional_steps.iter())
        {
            predicted_step_keys.push(step.step_key.clone());
            clone_replay_push_categories_from_text(
                &mut predicted_categories,
                &format!(
                    "{} {} {} {} {}",
                    step.step_key,
                    step.title,
                    step.instruction,
                    step.success_check,
                    step.expected_artifacts.join(" ")
                ),
            );
        }
        for step in &directive.required_steps {
            predicted_required_steps.push(format!("{}:{}", step.routine_key, step.step_key));
        }
        for gate in &directive.approval_gates {
            predicted_approval_gates.push(gate.gate_key.clone());
        }
        if predicted_categories.is_empty() {
            predicted_categories = normalize_replay_categories(Vec::new(), &directive.query);
        } else {
            predicted_categories = clone_replay_unique_sorted(predicted_categories);
        }
        predicted_routine_keys = clone_replay_unique_sorted(predicted_routine_keys);
        predicted_step_keys = clone_replay_unique_sorted(predicted_step_keys);
        predicted_required_steps = clone_replay_unique_sorted(predicted_required_steps);
        predicted_approval_gates = clone_replay_unique_sorted(predicted_approval_gates);
        Ok(PersonalPreferenceCloneDirectivePrediction {
            case_id: case.case_id.clone(),
            query: case.query.clone(),
            mode: directive.mode.clone(),
            predicted_categories,
            predicted_routine_keys,
            predicted_step_keys,
            predicted_required_steps,
            predicted_approval_gates,
            confidence: directive.confidence,
            directive,
            notes: vec![
                "Prediction was compiled by replaying the clone directive controller for this case."
                    .to_string(),
            ],
        })
    }

    pub fn run_clone_replay_suite(
        &self,
        ci_subset: bool,
        limit: Option<usize>,
        threshold: Option<f32>,
        options: PersonalPreferencesCloneOptions,
    ) -> Result<PersonalPreferenceCloneReplaySuite> {
        let threshold = threshold.unwrap_or(0.6).clamp(0.0, 1.0);
        let dataset =
            self.build_clone_replay_dataset(ci_subset, limit, options.current_repo_root.clone())?;
        let mut results = Vec::new();
        for case in dataset.cases {
            let case_options = PersonalPreferencesCloneOptions {
                mode: Some(case.mode.clone()),
                allow_sensitive: options.allow_sensitive,
                current_repo_root: case
                    .current_repo_root
                    .clone()
                    .or_else(|| options.current_repo_root.clone()),
                max_records: options.max_records.or(Some(12)),
                budget_tokens: options.budget_tokens.or(Some(1024)),
            };
            let prediction = self.predict_clone_next_directive(&case, case_options.clone())?;
            let evaluation = self.evaluate_clone_replay(
                &case.query,
                case_options,
                case.expected_categories.clone(),
            )?;
            let mut predicted_categories = prediction.predicted_categories.clone();
            predicted_categories.extend(evaluation.matched_categories.clone());
            let category_recall =
                clone_replay_set_recall(&case.expected_categories, &predicted_categories);
            let routine_recall = clone_replay_set_recall(
                &case.expected_routine_keys,
                &prediction.predicted_routine_keys,
            );
            let step_recall =
                clone_replay_set_recall(&case.expected_step_keys, &prediction.predicted_step_keys);
            let approval_gate_expected = clone_replay_approval_expected(&case);
            let approval_gate_predicted = !prediction.predicted_approval_gates.is_empty();
            let approval_gate_accuracy = if approval_gate_expected == approval_gate_predicted {
                1.0
            } else {
                0.0
            };
            let score = (category_recall * 0.30
                + routine_recall * 0.25
                + step_recall * 0.25
                + evaluation.overall_score * 0.15
                + approval_gate_accuracy * 0.05)
                .clamp(0.0, 1.0);
            let passed = score >= threshold;
            let mut notes = Vec::new();
            if !passed {
                notes.push(format!(
                    "Case score {score:.2} was below threshold {threshold:.2}."
                ));
            }
            results.push(PersonalPreferenceCloneReplayCaseResult {
                case,
                prediction,
                evaluation,
                category_recall,
                routine_recall,
                step_recall,
                approval_gate_expected,
                approval_gate_predicted,
                approval_gate_accuracy,
                score,
                passed,
                notes,
            });
        }
        let metrics = clone_replay_metrics(&results);
        let generated_at_ms = now_ms();
        let suite = PersonalPreferenceCloneReplaySuite {
            generated_at_ms,
            ci_subset,
            threshold,
            metrics,
            results,
            notes: vec![
                "Replay suite compares expected operator-routine directives against deterministic clone directive predictions."
                    .to_string(),
                "Scores are aggregate recall metrics over workflow categories, routine keys, step keys, approval gates, and existing evidence-pack replay evaluation."
                    .to_string(),
            ],
        };
        let conn = open_db(&self.db_path)?;
        conn.execute(
            "INSERT INTO pp_clone_evaluations(
                id, mode, score, query, notes, created_at_ms, metadata_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                format!("clone_replay_suite_{}", Uuid::new_v4()),
                if suite.ci_subset {
                    "replay_suite:ci"
                } else {
                    "replay_suite:full"
                },
                suite.metrics.average_score,
                if suite.ci_subset {
                    "ci_replay_suite"
                } else {
                    "full_replay_suite"
                },
                suite.notes.join(" "),
                generated_at_ms,
                serde_json::to_string(&json!({
                    "threshold": suite.threshold,
                    "metrics": &suite.metrics,
                    "case_summaries": suite.results.iter().map(|result| {
                        json!({
                            "case_id": &result.case.case_id,
                            "score": result.score,
                            "passed": result.passed,
                            "category_recall": result.category_recall,
                            "routine_recall": result.routine_recall,
                            "step_recall": result.step_recall,
                            "approval_gate_accuracy": result.approval_gate_accuracy,
                        })
                    }).collect::<Vec<_>>(),
                }))?,
            ],
        )?;
        Ok(suite)
    }

    pub fn build_context(
        &self,
        query: &str,
        options: PersonalPreferencesContextOptions,
    ) -> Result<PersonalPreferencesContextAssembly> {
        let mut pack = self.build_clone_context_pack(
            query,
            PersonalPreferencesCloneOptions {
                mode: Some(CLONE_MODE_ADAPTIVE.to_string()),
                allow_sensitive: options.allow_sensitive,
                current_repo_root: options.current_repo_root,
                max_records: Some(options.max_records),
                budget_tokens: Some(options.budget_tokens),
            },
        )?;
        let used_tokens = pack
            .items
            .iter()
            .map(|item| item.token_estimate)
            .sum::<usize>();
        let remaining_tokens = options.budget_tokens.saturating_sub(used_tokens);
        let remaining_items = options.max_records.saturating_sub(pack.items.len());
        let generated_skill_items =
            self.generated_skill_context_items(query, remaining_items, remaining_tokens)?;
        let generated_skill_count = generated_skill_items.len();
        pack.items.extend(generated_skill_items);
        Ok(PersonalPreferencesContextAssembly {
            trace: PersonalPreferencesContextTrace {
                available: pack.trace.len() + generated_skill_count,
                selected: pack.items.len(),
                truncated: pack.truncated_items,
                budget_tokens: options.budget_tokens,
            },
            items: pack.items,
        })
    }

    pub fn build_clone_context_pack(
        &self,
        query: &str,
        options: PersonalPreferencesCloneOptions,
    ) -> Result<PersonalPreferenceCloneContextPack> {
        let conn = open_db(&self.db_path)?;
        let policies = load_category_policy_map(&conn)?;
        let mode = normalize_clone_mode(options.mode.as_deref().unwrap_or(CLONE_MODE_ADAPTIVE));
        let max_records = options.max_records.unwrap_or(8).clamp(1, 64);
        let budget_tokens = options.budget_tokens.unwrap_or(600).clamp(32, 4096);
        let current_repo_root = options.current_repo_root.clone();
        let mut candidates =
            load_clone_context_candidates(&conn, query, &mode, options.allow_sensitive)?;
        let available = candidates.len();
        if let Some(current_repo_root) = current_repo_root.as_deref() {
            for bridge in load_claim_bridge_candidates(
                &conn,
                current_repo_root,
                options.allow_sensitive,
                &policies,
            )? {
                candidates.push(bridge);
            }
        }
        candidates.sort_by(|left, right| {
            right
                .score
                .partial_cmp(&left.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    right
                        .claim
                        .confidence
                        .partial_cmp(&left.claim.confidence)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| right.claim.updated_at_ms.cmp(&left.claim.updated_at_ms))
        });
        let mut used = 0usize;
        let mut truncated = 0usize;
        let mut excluded_by_policy = 0usize;
        let mut items = Vec::new();
        let mut trace = Vec::new();
        for candidate in candidates {
            if items.len() >= max_records || used >= budget_tokens {
                truncated += 1;
                continue;
            }
            if !candidate.allowed {
                excluded_by_policy += 1;
                continue;
            }
            let token_estimate = estimate_tokens(&candidate.content);
            let remaining = budget_tokens.saturating_sub(used);
            let rendered = if token_estimate > remaining {
                let snippet = truncate_to_tokens(&candidate.content, remaining);
                if snippet.is_empty() {
                    truncated += 1;
                    continue;
                }
                truncated += 1;
                snippet
            } else {
                candidate.content.clone()
            };
            let rendered_tokens = estimate_tokens(&rendered);
            used = used.saturating_add(rendered_tokens);
            items.push(PersonalPreferencesContextItem {
                section: candidate.section.clone(),
                content: rendered,
                category: candidate.claim.category.clone(),
                record_type: candidate.record_type.clone(),
                confidence: candidate.claim.confidence,
                claim_id: Some(candidate.claim.id.clone()),
                claim_origin: Some(candidate.claim.claim_origin.clone()),
                truth_status: Some(candidate.claim.truth_status.clone()),
                source_repo_root: candidate.source_repo_root.clone(),
                token_estimate: rendered_tokens,
            });
            trace.push(PersonalPreferenceCloneTraceItem {
                claim_id: candidate.claim.id.clone(),
                section: candidate.section,
                reason: candidate.reason,
                score: candidate.score,
                claim_origin: candidate.claim.claim_origin.clone(),
                truth_status: candidate.claim.truth_status.clone(),
                confidence: candidate.claim.confidence,
                sensitive: is_sensitive_level(&candidate.claim.sensitivity),
            });
        }
        let summary = render_clone_context_summary(&items);
        let created_at_ms = now_ms();
        let pack_id = format!("clone_pack_{}", Uuid::new_v4());
        conn.execute(
            "INSERT INTO pp_clone_context_packs(
                id, mode, query, query_hash, current_repo_root, summary, explanation_json, created_at_ms, metadata_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                pack_id,
                mode,
                query,
                sha256_hex(query),
                current_repo_root,
                summary,
                serde_json::to_string(&trace)?,
                created_at_ms,
                serde_json::to_string(&json!({
                    "selected": items.len(),
                    "available": available,
                    "excluded_by_policy": excluded_by_policy,
                    "truncated_items": truncated,
                }))?,
            ],
        )?;
        upsert_clone_profile(&conn, &mode, &summary, created_at_ms)?;
        Ok(PersonalPreferenceCloneContextPack {
            mode,
            query: query.to_string(),
            summary,
            items,
            trace,
            excluded_by_policy,
            truncated_items: truncated,
            created_at_ms,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_clone_directive(
        &self,
        query: &str,
        options: PersonalPreferencesCloneOptions,
        agent_id: Option<String>,
        task_type: Option<String>,
        requested_risk_level: Option<String>,
        current_files: Vec<String>,
        current_plan_path: Option<String>,
        enforcement_level: Option<String>,
    ) -> Result<PersonalPreferenceCloneDirective> {
        let pack = self.build_clone_context_pack(query, options.clone())?;
        let conn = open_db(&self.db_path)?;
        let routines = load_operator_routines(&conn, 64, 0)?
            .into_iter()
            .filter(|routine| routine.status != "excluded")
            .collect::<Vec<_>>();
        let task_type = normalize_clone_directive_optional(task_type);
        let requested_risk_level = normalize_clone_directive_optional(requested_risk_level);
        let current_plan_path = normalize_clone_directive_optional(current_plan_path);
        let current_files = normalize_clone_directive_current_files(current_files);
        let agent_id = normalize_clone_directive_optional(agent_id);
        let inferred_task_phase = infer_clone_directive_task_phase(
            query,
            task_type.as_deref(),
            current_plan_path.as_deref(),
        );
        let selected_routines = select_clone_directive_routines(
            routines,
            query,
            &pack.mode,
            task_type.as_deref(),
            &inferred_task_phase,
            current_plan_path.as_deref(),
            &current_files,
        );

        let mut required_steps = Vec::new();
        let mut optional_steps = Vec::new();
        for routine in &selected_routines {
            for step in &routine.steps {
                let directive_step = clone_directive_step_from_routine(routine, step);
                if step.required || step.approval_required {
                    required_steps.push(directive_step);
                } else {
                    optional_steps.push(directive_step);
                }
            }
        }
        required_steps.sort_by(|left, right| {
            left.routine_key
                .cmp(&right.routine_key)
                .then_with(|| left.step_order.cmp(&right.step_order))
        });
        optional_steps.sort_by(|left, right| {
            left.routine_key
                .cmp(&right.routine_key)
                .then_with(|| left.step_order.cmp(&right.step_order))
        });

        let risk_level =
            clone_directive_max_risk(requested_risk_level.as_deref(), &selected_routines);
        let approval_gates = clone_directive_approval_gates(&selected_routines, &risk_level);
        let enforcement_level = normalize_clone_directive_enforcement_level(
            enforcement_level.as_deref(),
            &risk_level,
            &inferred_task_phase,
            &approval_gates,
        );
        let required_artifacts =
            clone_directive_required_artifacts(&required_steps, current_plan_path.as_deref());
        let validation_plan = clone_directive_validation_plan(&required_steps);
        let memory_to_load =
            clone_directive_memory_to_load(agent_id.as_deref(), &pack, &required_steps);
        let stop_conditions = clone_directive_stop_conditions(&risk_level, &approval_gates);
        let avoidances = clone_directive_avoidances();
        let confidence =
            clone_directive_confidence(&selected_routines, &required_steps, pack.items.len());
        let evidence_summary =
            clone_directive_evidence_summary(&selected_routines, &required_steps, pack.items.len());
        let mut notes = Vec::new();
        if selected_routines.is_empty() {
            notes.push("No executable operator routine matched the request.".to_string());
        }
        if approval_gates.is_empty() {
            notes.push("No approval gate was required by the selected routines.".to_string());
        }
        if optional_steps.is_empty() {
            notes.push("No optional routine steps were selected.".to_string());
        }
        if confidence < 0.5 {
            notes.push(
                "Directive confidence is low; treat this as advisory and prefer repo truth."
                    .to_string(),
            );
        }

        Ok(PersonalPreferenceCloneDirective {
            agent_id,
            mode: pack.mode.clone(),
            enforcement_level,
            query: pack.query.clone(),
            task_type,
            risk_level,
            inferred_task_phase,
            current_repo_root: options.current_repo_root.clone(),
            current_files,
            current_plan_path,
            selected_routines: selected_routines
                .iter()
                .map(clone_directive_routine_summary)
                .collect(),
            required_steps,
            optional_steps,
            required_artifacts,
            approval_gates,
            validation_plan,
            memory_to_load,
            stop_conditions,
            avoidances,
            confidence,
            evidence_summary,
            pack,
            generated_at_ms: now_ms(),
            notes,
        })
    }

    pub fn explain_clone_context(
        &self,
        query: &str,
        options: PersonalPreferencesCloneOptions,
    ) -> Result<PersonalPreferenceCloneExplanation> {
        let pack = self.build_clone_context_pack(query, options)?;
        let conn = open_db(&self.db_path)?;
        let included_claims = pack
            .trace
            .iter()
            .filter_map(|trace| {
                let claim = load_claim_by_id(&conn, &trace.claim_id).ok().flatten()?;
                let content = pack
                    .items
                    .iter()
                    .find(|item| item.claim_id.as_deref() == Some(trace.claim_id.as_str()))
                    .map(|item| item.content.clone())
                    .unwrap_or_else(|| render_claim_content(&claim));
                let source_repo_root = pack
                    .items
                    .iter()
                    .find(|item| item.claim_id.as_deref() == Some(trace.claim_id.as_str()))
                    .and_then(|item| item.source_repo_root.clone());
                Some(PersonalPreferenceCloneExplanationRecord {
                    claim_id: trace.claim_id.clone(),
                    section: trace.section.clone(),
                    content,
                    reason: trace.reason.clone(),
                    score: trace.score,
                    claim_origin: trace.claim_origin.clone(),
                    truth_status: trace.truth_status.clone(),
                    confidence: trace.confidence,
                    sensitive: trace.sensitive,
                    source_repo_root,
                    evidence_summary: claim.evidence_summary.clone(),
                })
            })
            .collect::<Vec<_>>();
        Ok(PersonalPreferenceCloneExplanation {
            pack,
            included_claims,
            ranking_factors: vec![
                "Ranking prefers explicit/confirmed/high-stability claims before weaker inferences."
                    .to_string(),
                "Scores combine confidence, truth status, stability, query term match, and mode-specific section boosts."
                    .to_string(),
                "Explicit user corrections receive an additional priority boost during clone-pack selection."
                    .to_string(),
                "Broad operator-style queries boost synthesized routines and repeated workflow, quality, and delivery claims while down-ranking one-off environment facts."
                    .to_string(),
            ],
            policy_notes: vec![
                "Repo truth still outranks clone inference; clone packs only shape preference-sensitive behavior."
                    .to_string(),
                "Sensitive claims are omitted unless allow_sensitive is enabled and policy allows them."
                    .to_string(),
                "Excluded-by-policy and truncated counts reflect pack-level filtering, not hidden inclusion."
                    .to_string(),
            ],
        })
    }

    pub fn evaluate_clone_context(
        &self,
        query: &str,
        options: PersonalPreferencesCloneOptions,
    ) -> Result<PersonalPreferenceCloneEvaluation> {
        let pack = self.build_clone_context_pack(query, options.clone())?;
        let explicit_selected = pack
            .trace
            .iter()
            .filter(|item| {
                matches!(
                    item.claim_origin.as_str(),
                    CLAIM_ORIGIN_EXPLICIT_USER_STATEMENT
                        | CLAIM_ORIGIN_EXPLICIT_USER_CORRECTION
                        | CLAIM_ORIGIN_MANUAL_REVIEW_ENTRY
                )
            })
            .count();
        let inferred_selected = pack
            .trace
            .iter()
            .filter(|item| {
                matches!(
                    item.claim_origin.as_str(),
                    CLAIM_ORIGIN_CROSS_SESSION_INFERENCE | CLAIM_ORIGIN_ENVIRONMENTAL_INFERENCE
                )
            })
            .count();
        let confirmed_selected = pack
            .trace
            .iter()
            .filter(|item| item.truth_status == TRUTH_STATUS_CONFIRMED)
            .count();
        let current_selected = pack
            .items
            .iter()
            .filter(|item| {
                matches!(
                    item.section.as_str(),
                    "active_project_and_strategic_context"
                        | "current_workflow_and_quality_expectations"
                )
            })
            .count();
        let bridge_selected = pack
            .items
            .iter()
            .filter(|item| item.section == "relevant_cross_project_bridges")
            .count();
        let style_selected = pack
            .items
            .iter()
            .filter(|item| item.section == "relevant_communication_style_expectations")
            .count();
        let decision_patterns_selected = pack
            .items
            .iter()
            .filter(|item| item.record_type == "decision_pattern")
            .count();
        let overall_score =
            (((explicit_selected * 4 + confirmed_selected * 3 + bridge_selected * 2) as f32)
                / ((pack.items.len().max(1) * 4) as f32))
                .clamp(0.0, 1.0);
        let mut notes = Vec::new();
        if explicit_selected == 0 {
            notes.push("No explicit user statements were selected.".to_string());
        }
        if style_selected == 0 {
            notes.push("No communication-style expectations were selected.".to_string());
        }
        if bridge_selected == 0 {
            notes.push("No cross-project bridge hints were selected.".to_string());
        }
        let created_at_ms = now_ms();
        let conn = open_db(&self.db_path)?;
        conn.execute(
            "INSERT INTO pp_clone_evaluations(
                id, mode, score, query, notes, created_at_ms, metadata_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                format!("clone_eval_{}", Uuid::new_v4()),
                pack.mode,
                overall_score,
                pack.query,
                notes.join(" "),
                created_at_ms,
                serde_json::to_string(&json!({
                    "explicit_selected": explicit_selected,
                    "inferred_selected": inferred_selected,
                    "confirmed_selected": confirmed_selected,
                    "current_selected": current_selected,
                    "bridge_selected": bridge_selected,
                    "style_selected": style_selected,
                    "decision_patterns_selected": decision_patterns_selected,
                }))?,
            ],
        )?;
        Ok(PersonalPreferenceCloneEvaluation {
            mode: pack.mode,
            query: pack.query,
            overall_score,
            explicit_selected,
            inferred_selected,
            confirmed_selected,
            current_selected,
            bridge_selected,
            style_selected,
            decision_patterns_selected,
            notes,
        })
    }

    pub fn export_bundle(
        &self,
        capture_id: Option<&str>,
    ) -> Result<PersonalPreferencesExportSummary> {
        let conn = open_db(&self.db_path)?;
        let captures = if let Some(capture_id) = capture_id {
            self.read_capture(capture_id)?
                .into_iter()
                .collect::<Vec<_>>()
        } else {
            let mut list = self.list_captures(None, 10_000, 0)?.items;
            for capture in &mut list {
                capture.messages = self.messages_for_capture(&capture.id, &capture.metadata)?;
            }
            list
        };
        let capture_ids = captures
            .iter()
            .map(|item| item.id.clone())
            .collect::<Vec<_>>();
        let records = if capture_ids.is_empty() {
            Vec::new()
        } else {
            load_records_for_capture_ids(&conn, &capture_ids)?
        };
        let full_export = capture_id.is_none();
        let claims = if full_export {
            export_table_json(&conn, "pp_claims", "updated_at_ms DESC, created_at_ms DESC")?
        } else {
            export_table_json_where_any_in(
                &conn,
                "pp_claims",
                &[("capture_id", capture_ids.clone())],
                "updated_at_ms DESC, created_at_ms DESC",
            )?
        };
        let claim_ids = export_row_ids(&claims);
        let claim_versions = if full_export {
            export_table_json(&conn, "pp_claim_versions", "created_at_ms DESC")?
        } else {
            export_table_json_where_any_in(
                &conn,
                "pp_claim_versions",
                &[("claim_id", claim_ids.clone())],
                "created_at_ms DESC",
            )?
        };
        let claim_evidence = if full_export {
            export_table_json(&conn, "pp_claim_evidence", "created_at_ms DESC")?
        } else {
            export_table_json_where_any_in(
                &conn,
                "pp_claim_evidence",
                &[
                    ("claim_id", claim_ids.clone()),
                    ("capture_id", capture_ids.clone()),
                ],
                "created_at_ms DESC",
            )?
        };
        let claim_links = if full_export {
            export_table_json(&conn, "pp_claim_links", "created_at_ms DESC")?
        } else {
            export_table_json_where_any_in(
                &conn,
                "pp_claim_links",
                &[
                    ("claim_id", claim_ids.clone()),
                    ("linked_claim_id", claim_ids.clone()),
                ],
                "created_at_ms DESC",
            )?
        };
        let feedback_events = if full_export {
            export_table_json(&conn, "pp_feedback_events", "created_at_ms DESC")?
        } else {
            export_table_json_where_any_in(
                &conn,
                "pp_feedback_events",
                &[
                    ("claim_id", claim_ids.clone()),
                    ("capture_id", capture_ids.clone()),
                ],
                "created_at_ms DESC",
            )?
        };
        let identity_snapshots = if full_export {
            export_table_json(&conn, "pp_identity_snapshots", "created_at_ms DESC")?
        } else {
            export_table_json_where_like_any(
                &conn,
                "pp_identity_snapshots",
                "metadata_json",
                &capture_ids,
                "created_at_ms DESC",
            )?
        };
        let snapshot_ids = export_row_ids(&identity_snapshots);
        let decision_patterns = if full_export {
            export_table_json(&conn, "pp_decision_patterns", "updated_at_ms DESC")?
        } else {
            export_table_json_where_any_in(
                &conn,
                "pp_decision_patterns",
                &[("snapshot_id", snapshot_ids.clone())],
                "updated_at_ms DESC",
            )?
        };
        let style_signals = if full_export {
            export_table_json(&conn, "pp_style_signals", "updated_at_ms DESC")?
        } else {
            export_table_json_where_any_in(
                &conn,
                "pp_style_signals",
                &[("snapshot_id", snapshot_ids.clone())],
                "updated_at_ms DESC",
            )?
        };
        let clone_profiles = if full_export {
            export_table_json(&conn, "pp_clone_profiles", "updated_at_ms DESC")?
        } else {
            Vec::new()
        };
        let clone_context_packs = if full_export {
            export_table_json(&conn, "pp_clone_context_packs", "created_at_ms DESC")?
        } else {
            Vec::new()
        };
        let clone_evaluations = if full_export {
            export_table_json(&conn, "pp_clone_evaluations", "created_at_ms DESC")?
        } else {
            Vec::new()
        };
        let project_timelines = if full_export {
            export_table_json(&conn, "pp_project_timelines", "updated_at_ms DESC")?
        } else {
            export_table_json_where_any_in(
                &conn,
                "pp_project_timelines",
                &[
                    ("claim_id", claim_ids.clone()),
                    ("snapshot_id", snapshot_ids.clone()),
                ],
                "updated_at_ms DESC",
            )?
        };
        let goal_graph = if full_export {
            export_table_json(&conn, "pp_goal_graph", "updated_at_ms DESC")?
        } else {
            export_table_json_where_any_in(
                &conn,
                "pp_goal_graph",
                &[
                    ("claim_id", claim_ids.clone()),
                    ("snapshot_id", snapshot_ids.clone()),
                ],
                "updated_at_ms DESC",
            )?
        };
        let operator_routines = if full_export {
            export_table_json(&conn, "pp_operator_routines", "updated_at_ms DESC")?
        } else {
            Vec::new()
        };
        let routine_ids = export_row_ids(&operator_routines);
        let operator_routine_steps = if full_export {
            export_table_json(&conn, "pp_operator_routine_steps", "step_order ASC")?
        } else {
            export_table_json_where_any_in(
                &conn,
                "pp_operator_routine_steps",
                &[("routine_id", routine_ids.clone())],
                "step_order ASC",
            )?
        };
        let override_rules = if full_export {
            export_table_json(&conn, "pp_override_rules", "updated_at_ms DESC")?
        } else {
            export_table_json_where_any_in(
                &conn,
                "pp_override_rules",
                &[("claim_id", claim_ids.clone())],
                "updated_at_ms DESC",
            )?
        };
        let redaction_spans = if full_export {
            export_table_json(&conn, "pp_redaction_spans", "created_at_ms DESC")?
        } else {
            export_table_json_where_any_in(
                &conn,
                "pp_redaction_spans",
                &[
                    ("claim_id", claim_ids.clone()),
                    ("capture_id", capture_ids.clone()),
                ],
                "created_at_ms DESC",
            )?
        };
        let retention_policies = if full_export {
            export_table_json(&conn, "pp_retention_policies", "updated_at_ms DESC")?
        } else {
            Vec::new()
        };
        let payload = json!({
            "schema_version": SCHEMA_VERSION,
            "exported_at_ms": now_ms(),
            "storage_root": self.root_dir.display().to_string(),
            "scope": {
                "capture_id": capture_id,
                "full_export": full_export,
            },
            "captures": captures,
            "records": records,
            "claims": claims,
            "claim_versions": claim_versions,
            "claim_evidence": claim_evidence,
            "claim_links": claim_links,
            "feedback_events": feedback_events,
            "identity_snapshots": identity_snapshots,
            "decision_patterns": decision_patterns,
            "style_signals": style_signals,
            "clone_profiles": clone_profiles,
            "clone_context_packs": clone_context_packs,
            "clone_evaluations": clone_evaluations,
            "project_timelines": project_timelines,
            "goal_graph": goal_graph,
            "operator_routines": operator_routines,
            "operator_routine_steps": operator_routine_steps,
            "override_rules": override_rules,
            "redaction_spans": redaction_spans,
            "retention_policies": retention_policies,
        });
        let file_name = match capture_id {
            Some(id) => format!("personal-preferences-{id}-{}.json", now_ms()),
            None => format!("personal-preferences-export-{}.json", now_ms()),
        };
        let path = self.exports_dir.join(file_name);
        fs::write(&path, serde_json::to_vec_pretty(&payload)?)
            .with_context(|| format!("write {}", path.display()))?;
        Ok(PersonalPreferencesExportSummary {
            path: path.display().to_string(),
            captures: payload
                .get("captures")
                .and_then(Value::as_array)
                .map(|items| items.len())
                .unwrap_or(0),
            derived_records: payload
                .get("records")
                .and_then(Value::as_array)
                .map(|items| items.len())
                .unwrap_or(0),
            claims: payload_array_len(&payload, "claims"),
            claim_versions: payload_array_len(&payload, "claim_versions"),
            claim_evidence: payload_array_len(&payload, "claim_evidence"),
            claim_links: payload_array_len(&payload, "claim_links"),
            feedback_events: payload_array_len(&payload, "feedback_events"),
            identity_snapshots: payload_array_len(&payload, "identity_snapshots"),
            decision_patterns: payload_array_len(&payload, "decision_patterns"),
            style_signals: payload_array_len(&payload, "style_signals"),
            clone_profiles: payload_array_len(&payload, "clone_profiles"),
            clone_context_packs: payload_array_len(&payload, "clone_context_packs"),
            clone_evaluations: payload_array_len(&payload, "clone_evaluations"),
            project_timelines: payload_array_len(&payload, "project_timelines"),
            goal_graph: payload_array_len(&payload, "goal_graph"),
            operator_routines: payload_array_len(&payload, "operator_routines"),
            operator_routine_steps: payload_array_len(&payload, "operator_routine_steps"),
            override_rules: payload_array_len(&payload, "override_rules"),
            redaction_spans: payload_array_len(&payload, "redaction_spans"),
            retention_policies: payload_array_len(&payload, "retention_policies"),
        })
    }

    pub fn redact_capture(&self, capture_id: &str) -> Result<PersonalPreferencesRedactionSummary> {
        let capture = self
            .read_capture(capture_id)?
            .ok_or_else(|| anyhow!("capture not found"))?;
        let now = now_ms();
        let conn = open_db(&self.db_path)?;
        conn.execute(
            "UPDATE captured_conversations
             SET transcript_text = ?2, archive_redacted_at_ms = ?3, updated_at_ms = ?3
             WHERE id = ?1",
            params![capture_id, REDACTED_TEXT, now],
        )?;
        conn.execute(
            "UPDATE captured_messages
             SET content = ?2
             WHERE capture_id = ?1",
            params![capture_id, REDACTED_TEXT],
        )?;
        conn.execute(
            "UPDATE pp_messages
             SET content = ?2
             WHERE capture_id = ?1",
            params![capture_id, REDACTED_TEXT],
        )?;
        let mut archive_redacted = false;
        if let Some(path) = capture.archive_path.as_deref() {
            let archive_path = Path::new(path);
            if archive_path.exists() {
                let mut envelope = self.read_archive_envelope(archive_path)?;
                for message in &mut envelope.request.messages {
                    message.content = REDACTED_TEXT.to_string();
                }
                envelope.request.transcript_text = Some(REDACTED_TEXT.to_string());
                envelope.request.summary_text = Some(REDACTED_TEXT.to_string());
                let cipher = resolve_cipher_from_metadata(&envelope.request.metadata);
                let protected = PersonalPreferencesArchiveEnvelope {
                    request: protect_capture_request_payload(&envelope.request, cipher.as_ref()),
                    ..envelope
                };
                fs::write(archive_path, serde_json::to_vec_pretty(&protected)?)
                    .with_context(|| format!("write {}", archive_path.display()))?;
                archive_redacted = true;
            }
        }
        write_redaction_span(
            &conn,
            capture_id,
            None,
            "capture_redact",
            None,
            None,
            REDACTED_TEXT,
            "capture redacted",
            &json!({ "archive_redacted": archive_redacted }),
            now,
        )?;
        self.write_tombstone(
            capture_id,
            "redact",
            json!({ "archive_redacted": archive_redacted }),
        )?;
        Ok(PersonalPreferencesRedactionSummary {
            capture_id: capture_id.to_string(),
            redacted: true,
            archive_redacted,
        })
    }

    pub fn delete_capture(&self, capture_id: &str) -> Result<PersonalPreferencesDeleteSummary> {
        let capture = self.read_capture(capture_id)?;
        let Some(capture) = capture else {
            return Ok(PersonalPreferencesDeleteSummary {
                capture_id: capture_id.to_string(),
                deleted: false,
                archive_deleted: false,
                records_deleted: 0,
            });
        };
        let conn = open_db(&self.db_path)?;
        let records_deleted = count_query_with_param(
            &conn,
            "SELECT COUNT(*) FROM derived_records WHERE capture_id = ?1",
            params![capture_id],
        )?;
        conn.execute(
            "DELETE FROM captured_conversations WHERE id = ?1",
            params![capture_id],
        )?;
        self.delete_queue_marker(capture_id)?;
        let archive_deleted = if let Some(path) = capture.archive_path.as_deref() {
            delete_if_exists(Path::new(path))?
        } else {
            false
        };
        self.write_tombstone(
            capture_id,
            "delete",
            json!({ "archive_deleted": archive_deleted, "records_deleted": records_deleted }),
        )?;
        Ok(PersonalPreferencesDeleteSummary {
            capture_id: capture_id.to_string(),
            deleted: true,
            archive_deleted,
            records_deleted,
        })
    }

    pub fn purge_all(&self, include_exports: bool) -> Result<PersonalPreferencesPurgeSummary> {
        let conn = open_db(&self.db_path)?;
        let captures_deleted = count_query(&conn, "SELECT COUNT(*) FROM captured_conversations")?;
        let derived_records_deleted = count_query(&conn, "SELECT COUNT(*) FROM derived_records")?;
        let operator_events_deleted =
            count_query(&conn, "SELECT COUNT(*) FROM pp_operator_events")?;
        conn.execute("DELETE FROM captured_conversations", [])?;
        conn.execute("DELETE FROM derived_records", [])?;
        conn.execute("DELETE FROM pp_sources", [])?;
        conn.execute("DELETE FROM pp_entities", [])?;
        conn.execute("DELETE FROM pp_operator_events", [])?;
        let archives_deleted = remove_dir_contents(&self.archive_dir)?;
        let queue_entries_deleted = remove_dir_contents(&self.queue_dir)?;
        let exports_deleted = if include_exports {
            remove_dir_contents(&self.exports_dir)?
        } else {
            0
        };
        self.write_tombstone(
            "all",
            "purge",
            json!({
                "captures_deleted": captures_deleted,
                "derived_records_deleted": derived_records_deleted,
                "operator_events_deleted": operator_events_deleted,
                "archives_deleted": archives_deleted,
                "queue_entries_deleted": queue_entries_deleted,
                "exports_deleted": exports_deleted,
            }),
        )?;
        Ok(PersonalPreferencesPurgeSummary {
            captures_deleted,
            derived_records_deleted,
            archives_deleted,
            queue_entries_deleted,
            exports_deleted,
        })
    }

    pub async fn process_pending_with_runner<F, Fut>(
        &self,
        limit: usize,
        mut runner: F,
    ) -> Result<PersonalPreferencesProcessingSummary>
    where
        F: FnMut(PersonalPreferenceDigestInput) -> Fut,
        Fut: Future<Output = Result<Option<PersonalPreferenceDigestOutput>>>,
    {
        let pending = self.list_pending_captures(limit.max(1))?;
        let mut summary = PersonalPreferencesProcessingSummary::default();
        for capture in pending {
            if !self.try_mark_capture_processing(&capture.id)? {
                continue;
            }
            summary.processed_captures += 1;
            let digest_job_id = self.create_digest_job(&capture.id)?;
            let mut processing_guard =
                ProcessingCaptureGuard::new(self, capture.id.clone(), digest_job_id.clone());
            let input = PersonalPreferenceDigestInput {
                capture: capture.clone(),
            };
            match runner(input).await {
                Ok(Some(output)) => {
                    let written =
                        self.complete_capture(&capture.id, Some(&digest_job_id), &output.records)?;
                    self.complete_digest_job(
                        &digest_job_id,
                        DIGEST_STATUS_COMPLETED,
                        None,
                        json!({ "records_written": written }),
                    )?;
                    processing_guard.disarm();
                    summary.records_written += written;
                    summary.completed_captures += 1;
                }
                Ok(None) => {
                    self.mark_capture_status(
                        &capture.id,
                        DIGEST_STATUS_PENDING,
                        Some("waiting_for_local_mcoda_agent"),
                    )?;
                    self.complete_digest_job(
                        &digest_job_id,
                        DIGEST_STATUS_PENDING,
                        Some("waiting_for_local_mcoda_agent"),
                        json!({}),
                    )?;
                    processing_guard.disarm();
                    summary.deferred_captures += 1;
                }
                Err(err) => {
                    self.mark_capture_status(
                        &capture.id,
                        DIGEST_STATUS_FAILED,
                        Some(&err.to_string()),
                    )?;
                    self.complete_digest_job(
                        &digest_job_id,
                        DIGEST_STATUS_FAILED,
                        Some(&err.to_string()),
                        json!({}),
                    )?;
                    processing_guard.disarm();
                    summary.failed_captures += 1;
                }
            }
        }
        Ok(summary)
    }

    pub fn requeue_captures_for_processing(
        &self,
        retry_failed: bool,
        retry_stale_processing_ms: Option<i64>,
        limit: Option<usize>,
    ) -> Result<usize> {
        if !retry_failed && retry_stale_processing_ms.is_none() {
            return Ok(0);
        }
        let limit = limit.unwrap_or(usize::MAX);
        if limit == 0 {
            return Ok(0);
        }
        let now = now_ms();
        let stale_before_ms =
            retry_stale_processing_ms.map(|value| now.saturating_sub(value.max(0)));
        let mut capture_ids = Vec::new();
        {
            let conn = open_db(&self.db_path)?;
            if retry_failed {
                let remaining = limit.saturating_sub(capture_ids.len());
                if remaining > 0 {
                    let mut stmt = conn.prepare(
                        "SELECT id
                         FROM captured_conversations
                         WHERE digest_status = ?1
                         ORDER BY updated_at_ms ASC, created_at_ms ASC
                         LIMIT ?2",
                    )?;
                    let mut rows = stmt.query(params![DIGEST_STATUS_FAILED, remaining as i64])?;
                    while let Some(row) = rows.next()? {
                        capture_ids.push(row.get::<_, String>(0)?);
                    }
                }
            }
            if let Some(stale_before_ms) = stale_before_ms {
                let remaining = limit.saturating_sub(capture_ids.len());
                if remaining > 0 {
                    let mut stmt = conn.prepare(
                        "SELECT id
                         FROM captured_conversations
                         WHERE digest_status = ?1 AND updated_at_ms <= ?2
                         ORDER BY updated_at_ms ASC, created_at_ms ASC
                         LIMIT ?3",
                    )?;
                    let mut rows = stmt.query(params![
                        DIGEST_STATUS_PROCESSING,
                        stale_before_ms,
                        remaining as i64
                    ])?;
                    while let Some(row) = rows.next()? {
                        capture_ids.push(row.get::<_, String>(0)?);
                    }
                }
            }
            for capture_id in &capture_ids {
                conn.execute(
                    "UPDATE captured_conversations
                     SET digest_status = ?2, updated_at_ms = ?3, last_digest_error = NULL
                     WHERE id = ?1
                       AND digest_status IN (?4, ?5)",
                    params![
                        capture_id,
                        DIGEST_STATUS_PENDING,
                        now,
                        DIGEST_STATUS_FAILED,
                        DIGEST_STATUS_PROCESSING
                    ],
                )?;
            }
        }
        for capture_id in &capture_ids {
            self.sync_queue_marker(capture_id, DIGEST_STATUS_PENDING)?;
        }
        Ok(capture_ids.len())
    }

    pub fn list_projectable_records(&self, limit: usize) -> Result<Vec<PersonalPreferenceRecord>> {
        let conn = open_db(&self.db_path)?;
        let mut records = load_all_records(&conn)?;
        records.retain(|record| {
            record.projected_to_profile_at_ms.is_none()
                && record.confidence >= 0.78
                && record.sensitivity == "low"
                && record.review_status == REVIEW_STATUS_APPROVED
                && map_record_to_profile_category(record).is_some()
        });
        records.sort_by(|left, right| {
            right
                .confidence
                .partial_cmp(&left.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| right.updated_at_ms.cmp(&left.updated_at_ms))
        });
        records.truncate(limit.max(1));
        Ok(records)
    }

    pub fn mark_records_projected(&self, record_ids: &[String]) -> Result<()> {
        if record_ids.is_empty() {
            return Ok(());
        }
        let conn = open_db(&self.db_path)?;
        let now = now_ms();
        for record_id in record_ids {
            conn.execute(
                "UPDATE derived_records
                 SET projected_to_profile_at_ms = ?2
                 WHERE id = ?1",
                params![record_id, now],
            )?;
        }
        Ok(())
    }

    fn list_pending_captures(&self, limit: usize) -> Result<Vec<PersonalPreferencesCaptureRecord>> {
        let conn = open_db(&self.db_path)?;
        let mut stmt = conn.prepare(
            "SELECT id, source, source_session_id, capture_kind, title, agent_id, transport,
                    repo_id, repo_root, scope_id, scope_label, started_at_ms, ended_at_ms,
                    created_at_ms, updated_at_ms, digest_status, transcript_text, metadata_json,
                    archive_path, raw_message_count, archive_redacted_at_ms, last_digest_error
             FROM captured_conversations
             WHERE digest_status = 'pending'
             ORDER BY created_at_ms ASC
             LIMIT ?1",
        )?;
        let mut rows = stmt.query(params![limit as i64])?;
        let mut captures = Vec::new();
        while let Some(row) = rows.next()? {
            let mut capture = row_to_capture(row)?;
            hydrate_capture_content(&mut capture);
            capture.messages = self.messages_for_capture(&capture.id, &capture.metadata)?;
            captures.push(capture);
        }
        Ok(captures)
    }

    fn messages_for_capture(
        &self,
        capture_id: &str,
        capture_metadata: &Value,
    ) -> Result<Vec<PersonalPreferencesMessage>> {
        let conn = open_db(&self.db_path)?;
        let cipher = resolve_cipher_from_metadata(capture_metadata);
        let mut stmt = conn.prepare(
            "SELECT role, content, created_at_ms, metadata_json
             FROM captured_messages
             WHERE capture_id = ?1
             ORDER BY ordinal ASC",
        )?;
        let mut rows = stmt.query(params![capture_id])?;
        let mut messages = Vec::new();
        while let Some(row) = rows.next()? {
            messages.push(PersonalPreferencesMessage {
                role: row.get::<_, String>(0)?,
                content: unprotect_text_for_reading(&row.get::<_, String>(1)?, cipher.as_ref()),
                created_at_ms: row.get(2)?,
                metadata: parse_json_value(&row.get::<_, String>(3)?),
            });
        }
        Ok(messages)
    }

    fn try_mark_capture_processing(&self, capture_id: &str) -> Result<bool> {
        let conn = open_db(&self.db_path)?;
        let updated = conn.execute(
            "UPDATE captured_conversations
             SET digest_status = ?2, updated_at_ms = ?3, last_digest_error = NULL
             WHERE id = ?1 AND digest_status = ?4",
            params![
                capture_id,
                DIGEST_STATUS_PROCESSING,
                now_ms(),
                DIGEST_STATUS_PENDING
            ],
        )?;
        if updated > 0 {
            self.sync_queue_marker(capture_id, DIGEST_STATUS_PROCESSING)?;
        }
        Ok(updated > 0)
    }

    fn mark_capture_status(
        &self,
        capture_id: &str,
        status: &str,
        error: Option<&str>,
    ) -> Result<()> {
        let conn = open_db(&self.db_path)?;
        conn.execute(
            "UPDATE captured_conversations
             SET digest_status = ?2, updated_at_ms = ?3, last_digest_error = ?4
             WHERE id = ?1",
            params![capture_id, status, now_ms(), error],
        )?;
        self.sync_queue_marker(capture_id, status)?;
        Ok(())
    }

    fn complete_capture(
        &self,
        capture_id: &str,
        digest_job_id: Option<&str>,
        records: &[PersonalPreferenceDigestRecord],
    ) -> Result<usize> {
        let capture = self
            .read_capture(capture_id)?
            .ok_or_else(|| anyhow!("capture not found"))?;
        let mut conn = open_db(&self.db_path)?;
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM derived_records WHERE capture_id = ?1",
            params![capture_id],
        )?;
        tx.execute(
            "DELETE FROM pp_snapshot_summaries WHERE capture_id = ?1",
            params![capture_id],
        )?;
        let now = now_ms();
        let mut inserted = 0usize;
        let mut seen = HashSet::new();
        let digest_run_id = format!("digest_run_{}", Uuid::new_v4());
        tx.execute(
            "INSERT INTO pp_digest_runs(
                id, job_id, capture_id, agent_id, model_hint, prompt_version, outcome_status,
                input_records, output_records, started_at_ms, finished_at_ms, error_text, metadata_json
             ) VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, ?7, 0, ?8, NULL, NULL, ?9)",
            params![
                digest_run_id,
                digest_job_id,
                capture_id,
                capture.agent_id,
                "personal_preferences_v1",
                DIGEST_STATUS_PROCESSING,
                records.len() as i64,
                now,
                serde_json::to_string(&json!({
                    "capture_kind": capture.capture_kind,
                    "source": capture.source,
                }))?,
            ],
        )?;
        let mut snapshot_lines = Vec::new();
        for record in records.iter().take(MAX_DIGEST_RECORDS_PER_CAPTURE) {
            let normalized = normalize_digest_record(record, &capture);
            if normalized.value.is_empty() {
                continue;
            }
            let dedupe_key = format!(
                "{}|{}|{}|{}|{}",
                normalized.record_type,
                normalized.category,
                normalized.subject,
                normalized.attribute.clone().unwrap_or_default(),
                normalized.value
            );
            if !seen.insert(dedupe_key) {
                continue;
            }
            let policy = ensure_category_policy_for_record(&tx, &normalized)?;
            let review_status = default_review_status_for_record(&normalized, &policy);
            let record_id = Uuid::new_v4().to_string();
            tx.execute(
                "INSERT INTO derived_records(
                    id, capture_id, record_type, category, subcategory, subject,
                    attribute, value, confidence, sensitivity, evidence,
                    created_at_ms, updated_at_ms, metadata_json, projected_to_profile_at_ms,
                    review_status, review_updated_at_ms
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, NULL, ?15, ?16)",
                params![
                    record_id,
                    capture_id,
                    normalized.record_type,
                    normalized.category,
                    normalized.subcategory,
                    normalized.subject,
                    normalized.attribute,
                    normalized.value,
                    normalized.confidence,
                    normalized.sensitivity,
                    normalized.evidence,
                    now,
                    now,
                    serde_json::to_string(&normalized.metadata)?,
                    review_status,
                    now,
                ],
            )?;
            if let Some(evidence) = normalized.evidence.as_deref() {
                tx.execute(
                    "INSERT INTO pp_evidence(
                        id, record_id, capture_id, evidence_text, metadata_json, created_at_ms
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        Uuid::new_v4().to_string(),
                        record_id,
                        capture_id,
                        evidence,
                        serde_json::to_string(&normalized.metadata)?,
                        now,
                    ],
                )?;
            }
            let materialized = BackfillRecord {
                id: record_id.clone(),
                capture_id: capture_id.to_string(),
                record_type: normalized.record_type.clone(),
                category: normalized.category.clone(),
                subcategory: normalized.subcategory.clone(),
                subject: normalized.subject.clone(),
                attribute: normalized.attribute.clone(),
                value: normalized.value.clone(),
                confidence: normalized.confidence.unwrap_or(0.5),
                sensitivity: normalized
                    .sensitivity
                    .clone()
                    .unwrap_or_else(|| "private".to_string()),
                evidence: normalized.evidence.clone(),
                created_at_ms: now,
                updated_at_ms: now,
                metadata: normalized.metadata.clone(),
                review_status: review_status.to_string(),
            };
            materialize_record_views(&tx, &materialized)?;
            upsert_claim_from_backfill_record(&tx, &materialized, "capture_digest")?;
            if let Some(repo_root) = capture
                .repo_root
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                if should_materialize_bridge(&normalized) {
                    tx.execute(
                        "INSERT INTO pp_cross_project_bridges(
                            id, record_id, source_repo_root, target_repo_root, bridge_key, summary,
                            created_at_ms
                        ) VALUES (?1, ?2, ?3, NULL, ?4, ?5, ?6)",
                        params![
                            Uuid::new_v4().to_string(),
                            record_id,
                            repo_root,
                            bridge_key_for_record(&normalized),
                            render_digest_record(&normalized),
                            now,
                        ],
                    )?;
                }
            }
            if snapshot_lines.len() < SNAPSHOT_SUMMARY_LIMIT {
                snapshot_lines.push(render_digest_record(&normalized));
            }
            inserted += 1;
        }
        tx.execute(
            "UPDATE pp_digest_runs
             SET outcome_status = ?2, output_records = ?3, finished_at_ms = ?4
             WHERE id = ?1",
            params![digest_run_id, DIGEST_STATUS_COMPLETED, inserted as i64, now],
        )?;
        tx.execute(
            "INSERT INTO pp_snapshot_summaries(
                id, capture_id, digest_run_id, summary, record_count, created_at_ms, metadata_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                format!("snapshot_{}_{}", capture_id, now),
                capture_id,
                digest_run_id,
                truncate_chars(&snapshot_lines.join(" | "), 640),
                inserted as i64,
                now,
                serde_json::to_string(&json!({
                    "capture_kind": capture.capture_kind,
                    "repo_root": capture.repo_root,
                }))?,
            ],
        )?;
        tx.execute(
            "UPDATE captured_conversations
             SET digest_status = ?2, updated_at_ms = ?3, last_digest_error = NULL
             WHERE id = ?1",
            params![capture_id, DIGEST_STATUS_COMPLETED, now],
        )?;
        let _ = rebuild_identity_snapshots_tx(&tx, Some(capture_id), "capture_complete")?;
        cleanup_orphan_entities(&tx)?;
        tx.commit()?;
        self.sync_queue_marker(capture_id, DIGEST_STATUS_COMPLETED)?;
        Ok(inserted)
    }

    fn write_archive_envelope(
        &self,
        capture_id: &str,
        created_at_ms: i64,
        request: &PersonalPreferencesCaptureRequest,
        cipher: Option<&ContentCipher>,
    ) -> Result<PathBuf> {
        let path = self.archive_dir.join(format!("{capture_id}.json"));
        let envelope = PersonalPreferencesArchiveEnvelope {
            capture_id: capture_id.to_string(),
            created_at_ms,
            request: protect_capture_request_payload(request, cipher),
        };
        fs::write(&path, serde_json::to_vec_pretty(&envelope)?)
            .with_context(|| format!("write {}", path.display()))?;
        Ok(path)
    }

    fn read_archive_envelope(&self, path: &Path) -> Result<PersonalPreferencesArchiveEnvelope> {
        let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let mut envelope: PersonalPreferencesArchiveEnvelope =
            serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
        let cipher = resolve_cipher_from_metadata(&envelope.request.metadata);
        envelope.request.transcript_text = envelope
            .request
            .transcript_text
            .map(|value| unprotect_text_for_reading(&value, cipher.as_ref()));
        envelope.request.summary_text = envelope
            .request
            .summary_text
            .map(|value| unprotect_text_for_reading(&value, cipher.as_ref()));
        envelope.request.messages = envelope
            .request
            .messages
            .into_iter()
            .map(|mut message| {
                message.content = unprotect_text_for_reading(&message.content, cipher.as_ref());
                message
            })
            .collect();
        Ok(envelope)
    }

    fn write_queue_marker(&self, capture: &PersonalPreferencesCaptureRecord) -> Result<()> {
        let path = self.queue_dir.join(format!("{}.json", capture.id));
        let payload = json!({
            "capture_id": capture.id,
            "source": capture.source,
            "repo_root": capture.repo_root,
            "created_at_ms": capture.created_at_ms,
            "digest_status": capture.digest_status,
        });
        fs::write(&path, serde_json::to_vec_pretty(&payload)?)
            .with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }

    fn delete_queue_marker(&self, capture_id: &str) -> Result<()> {
        let path = self.queue_dir.join(format!("{capture_id}.json"));
        let _ = delete_if_exists(&path)?;
        Ok(())
    }

    fn sync_queue_marker(&self, capture_id: &str, status: &str) -> Result<()> {
        if status == DIGEST_STATUS_PENDING {
            if let Some(capture) = self.read_capture(capture_id)? {
                return self.write_queue_marker(&capture);
            }
            return Ok(());
        }
        self.delete_queue_marker(capture_id)
    }

    fn create_digest_job(&self, capture_id: &str) -> Result<String> {
        let conn = open_db(&self.db_path)?;
        let now = now_ms();
        let job_id = Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO pp_digest_jobs(
                id, capture_id, status, error_text, started_at_ms, finished_at_ms,
                created_at_ms, updated_at_ms, metadata_json
             ) VALUES (?1, ?2, ?3, NULL, ?4, NULL, ?4, ?4, ?5)",
            params![
                job_id,
                capture_id,
                DIGEST_STATUS_PROCESSING,
                now,
                serde_json::to_string(&json!({}))?,
            ],
        )?;
        Ok(job_id)
    }

    fn complete_digest_job(
        &self,
        job_id: &str,
        status: &str,
        error: Option<&str>,
        metadata: Value,
    ) -> Result<()> {
        let conn = open_db(&self.db_path)?;
        let now = now_ms();
        conn.execute(
            "UPDATE pp_digest_jobs
             SET status = ?2,
                 error_text = ?3,
                 finished_at_ms = ?4,
                 updated_at_ms = ?4,
                 metadata_json = ?5
             WHERE id = ?1",
            params![
                job_id,
                status,
                error,
                now,
                serde_json::to_string(&metadata)?
            ],
        )?;
        Ok(())
    }

    fn write_tombstone(&self, capture_id: &str, action: &str, details: Value) -> Result<()> {
        let path = self
            .redactions_dir
            .join(format!("{}-{capture_id}-{action}.json", now_ms()));
        let payload = json!({
            "capture_id": capture_id,
            "action": action,
            "created_at_ms": now_ms(),
            "details": details,
        });
        fs::write(&path, serde_json::to_vec_pretty(&payload)?)
            .with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }

    fn has_external_session_ref(&self, external_ref: &str) -> Result<bool> {
        let external_ref = external_ref.trim();
        if external_ref.is_empty() {
            return Ok(false);
        }
        let conn = open_db(&self.db_path)?;
        let hash = sha256_hex(external_ref);
        Ok(conn
            .query_row(
                "SELECT 1 FROM pp_sessions WHERE external_ref_hash = ?1 LIMIT 1",
                params![hash],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }
}

fn normalize_clone_directive_optional(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn clone_replay_dataset_case_from_routine(
    routine: &PersonalPreferenceOperatorRoutine,
    generated_at_ms: i64,
    current_repo_root: Option<String>,
    index: usize,
) -> PersonalPreferenceCloneReplayDatasetCase {
    let query = routine
        .applies_when
        .iter()
        .find(|value| !value.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| {
            let purpose = if routine.purpose.trim().is_empty() {
                routine.summary.as_str()
            } else {
                routine.purpose.as_str()
            };
            format!("what should the operator do for {purpose}")
        });
    let mut expected_categories = clone_replay_categories_for_routine(routine);
    if expected_categories.is_empty() {
        expected_categories = normalize_replay_categories(Vec::new(), &query);
    }
    let mut expected_step_keys = routine
        .steps
        .iter()
        .filter(|step| step.required || step.approval_required)
        .map(|step| step.step_key.clone())
        .collect::<Vec<_>>();
    if expected_step_keys.is_empty() {
        expected_step_keys = routine
            .steps
            .iter()
            .take(5)
            .map(|step| step.step_key.clone())
            .collect::<Vec<_>>();
    }
    PersonalPreferenceCloneReplayDatasetCase {
        case_id: format!("routine:{}:v{}", routine.routine_key, routine.version),
        query,
        mode: clone_replay_mode_for_routine(routine),
        current_repo_root,
        expected_categories,
        expected_routine_keys: vec![routine.routine_key.clone()],
        expected_step_keys: clone_replay_unique_sorted(expected_step_keys),
        source: "operator_routine".to_string(),
        source_ids: vec![routine.id.clone()],
        ci_subset: routine.routine_key == "product_development_loop"
            || (index < 3 && routine.confidence >= 0.6),
        created_at_ms: generated_at_ms,
        notes: vec![
            "Expected outputs are derived from an executable operator routine.".to_string(),
            format!(
                "Routine support: {} claim(s), {} event(s), confidence {:.2}.",
                routine.support_count, routine.event_support_count, routine.confidence
            ),
        ],
    }
}

fn clone_replay_fallback_case(
    generated_at_ms: i64,
    current_repo_root: Option<String>,
) -> PersonalPreferenceCloneReplayDatasetCase {
    PersonalPreferenceCloneReplayDatasetCase {
        case_id: "fallback:product_development_loop:v1".to_string(),
        query: "how does the operator plan, implement, validate, and ship a product fix"
            .to_string(),
        mode: CLONE_MODE_PROJECT_BUILD.to_string(),
        current_repo_root,
        expected_categories: vec![
            "plan".to_string(),
            "progress_update".to_string(),
            "repo_inspection".to_string(),
            "implementation".to_string(),
            "gap_review".to_string(),
            "tests".to_string(),
        ],
        expected_routine_keys: vec!["product_development_loop".to_string()],
        expected_step_keys: vec![
            "plan_and_progress_docs".to_string(),
            "repo_context_and_impact".to_string(),
            "implement_scope".to_string(),
            "gap_review".to_string(),
            "validation_and_progress".to_string(),
        ],
        source: "fallback_workflow".to_string(),
        source_ids: Vec::new(),
        ci_subset: true,
        created_at_ms: generated_at_ms,
        notes: vec![
            "Fallback case keeps replay harness usable before enough routines are synthesized."
                .to_string(),
        ],
    }
}

fn clone_replay_mode_for_routine(routine: &PersonalPreferenceOperatorRoutine) -> String {
    match routine.routine_key.as_str() {
        "product_development_loop" => CLONE_MODE_PROJECT_BUILD.to_string(),
        "planning_progress_loop" => CLONE_MODE_PROJECT_BUILD.to_string(),
        "local_first_release_loop" => CLONE_MODE_RELEASE.to_string(),
        _ => CLONE_MODE_ADAPTIVE.to_string(),
    }
}

fn clone_replay_categories_for_routine(routine: &PersonalPreferenceOperatorRoutine) -> Vec<String> {
    let mut categories = Vec::new();
    clone_replay_push_categories_from_text(
        &mut categories,
        &format!(
            "{} {} {} {} {}",
            routine.routine_key,
            routine.title,
            routine.summary,
            routine.purpose,
            routine.trigger_terms.join(" ")
        ),
    );
    for applies_when in &routine.applies_when {
        clone_replay_push_categories_from_text(&mut categories, applies_when);
    }
    for step in &routine.steps {
        clone_replay_push_categories_from_text(
            &mut categories,
            &format!(
                "{} {} {} {} {} {} {}",
                step.step_key,
                step.title,
                step.instruction,
                step.tool_hints.join(" "),
                step.expected_artifacts.join(" "),
                step.success_check,
                step.failure_recovery
            ),
        );
    }
    clone_replay_unique_sorted(categories)
}

fn clone_replay_push_categories_from_text(target: &mut Vec<String>, text: &str) {
    let haystack = text.to_ascii_lowercase();
    if contains_any(
        &haystack,
        &["plan", "planning", "sds", "spec", "requirement", "roadmap"],
    ) {
        target.push("plan".to_string());
    }
    if contains_any(
        &haystack,
        &[
            "progress",
            "status",
            "checkpoint",
            "md file",
            "markdown",
            "handoff",
        ],
    ) {
        target.push("progress_update".to_string());
    }
    if contains_any(
        &haystack,
        &[
            "repo", "inspect", "search", "symbol", "ast", "impact", "dag", "graph",
        ],
    ) {
        target.push("repo_inspection".to_string());
    }
    if contains_any(
        &haystack,
        &[
            "implement",
            "implementation",
            "patch",
            "code",
            "fix",
            "change",
            "edit",
        ],
    ) {
        target.push("implementation".to_string());
    }
    if contains_any(
        &haystack,
        &[
            "gap",
            "compare",
            "missing",
            "align",
            "misaligned",
            "revisit",
            "audit",
        ],
    ) {
        target.push("gap_review".to_string());
    }
    if contains_any(
        &haystack,
        &[
            "test",
            "tests",
            "validate",
            "validation",
            "cargo",
            "check",
            "run-tests",
            "fmt",
        ],
    ) {
        target.push("tests".to_string());
    }
    if contains_any(
        &haystack,
        &["git", "commit", "tag", "push", "merge", "branch"],
    ) {
        target.push("commit".to_string());
    }
    if contains_any(
        &haystack,
        &["deploy", "deployment", "production", "release", "ship"],
    ) {
        target.push("deploy".to_string());
    }
    if contains_any(&haystack, &["backup", "restore", "rollback"]) {
        target.push("backup".to_string());
    }
}

fn clone_replay_unique_sorted(mut values: Vec<String>) -> Vec<String> {
    values.retain(|value| !value.trim().is_empty());
    values.sort();
    values.dedup();
    values
}

fn clone_replay_set_recall(expected: &[String], predicted: &[String]) -> f32 {
    if expected.is_empty() {
        return 1.0;
    }
    let predicted = predicted
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let matched = expected
        .iter()
        .filter(|value| predicted.contains(&value.to_ascii_lowercase()))
        .count();
    (matched as f32 / expected.len() as f32).clamp(0.0, 1.0)
}

fn clone_replay_approval_expected(case: &PersonalPreferenceCloneReplayDatasetCase) -> bool {
    case.expected_step_keys.iter().any(|value| {
        let value = value.to_ascii_lowercase();
        contains_any(
            &value,
            &[
                "approval",
                "approve",
                "deploy",
                "deployment",
                "release",
                "production",
                "backup",
                "rollback",
            ],
        )
    })
}

fn clone_replay_metrics(
    results: &[PersonalPreferenceCloneReplayCaseResult],
) -> PersonalPreferenceCloneReplayMetrics {
    let case_count = results.len();
    if case_count == 0 {
        return PersonalPreferenceCloneReplayMetrics {
            case_count: 0,
            passed_count: 0,
            failed_count: 0,
            average_score: 0.0,
            category_recall: 0.0,
            routine_recall: 0.0,
            step_recall: 0.0,
            approval_gate_accuracy: 0.0,
            min_score: 0.0,
            max_score: 0.0,
        };
    }
    let divisor = case_count as f32;
    let passed_count = results.iter().filter(|result| result.passed).count();
    PersonalPreferenceCloneReplayMetrics {
        case_count,
        passed_count,
        failed_count: case_count.saturating_sub(passed_count),
        average_score: results.iter().map(|result| result.score).sum::<f32>() / divisor,
        category_recall: results
            .iter()
            .map(|result| result.category_recall)
            .sum::<f32>()
            / divisor,
        routine_recall: results
            .iter()
            .map(|result| result.routine_recall)
            .sum::<f32>()
            / divisor,
        step_recall: results.iter().map(|result| result.step_recall).sum::<f32>() / divisor,
        approval_gate_accuracy: results
            .iter()
            .map(|result| result.approval_gate_accuracy)
            .sum::<f32>()
            / divisor,
        min_score: results
            .iter()
            .map(|result| result.score)
            .fold(1.0, f32::min),
        max_score: results
            .iter()
            .map(|result| result.score)
            .fold(0.0, f32::max),
    }
}

fn normalize_clone_directive_current_files(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() || !seen.insert(value.to_string()) {
            continue;
        }
        normalized.push(value.to_string());
        if normalized.len() >= 64 {
            break;
        }
    }
    normalized
}

fn infer_clone_directive_task_phase(
    query: &str,
    task_type: Option<&str>,
    current_plan_path: Option<&str>,
) -> String {
    let haystack = format!("{} {}", query, task_type.unwrap_or_default()).to_ascii_lowercase();
    if contains_any(
        &haystack,
        &[
            "deploy",
            "deployment",
            "release",
            "production",
            "commit",
            "tag",
            "push",
            "backup",
            "rollback",
        ],
    ) {
        "release".to_string()
    } else if contains_any(
        &haystack,
        &[
            "gap",
            "gaps",
            "missing",
            "misaligned",
            "compare",
            "review",
            "audit",
            "revisit",
        ],
    ) {
        "gap_review".to_string()
    } else if contains_any(
        &haystack,
        &[
            "test",
            "tests",
            "validate",
            "validation",
            "fmt",
            "format",
            "check",
        ],
    ) {
        "validation".to_string()
    } else if contains_any(&haystack, &["plan", "sds", "prd", "spec", "proposal"]) {
        "planning".to_string()
    } else if current_plan_path.is_some()
        || contains_any(
            &haystack,
            &["build", "code", "fix", "implement", "continue", "phase"],
        )
    {
        "implementation".to_string()
    } else {
        "general".to_string()
    }
}

fn select_clone_directive_routines(
    routines: Vec<PersonalPreferenceOperatorRoutine>,
    query: &str,
    mode: &str,
    task_type: Option<&str>,
    inferred_task_phase: &str,
    current_plan_path: Option<&str>,
    current_files: &[String],
) -> Vec<PersonalPreferenceOperatorRoutine> {
    let mut scored = routines
        .into_iter()
        .map(|routine| {
            let score = clone_directive_routine_score(
                &routine,
                query,
                mode,
                task_type,
                inferred_task_phase,
                current_plan_path,
                current_files,
            );
            let relevant = routine_is_relevant_to_query(&routine, query) || score >= 1.5;
            (score, relevant, routine)
        })
        .collect::<Vec<_>>();
    scored.sort_by(|left, right| {
        right
            .0
            .partial_cmp(&left.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| right.2.support_count.cmp(&left.2.support_count))
            .then_with(|| right.2.event_support_count.cmp(&left.2.event_support_count))
    });
    let selected = scored
        .iter()
        .filter(|(_, relevant, _)| *relevant)
        .take(4)
        .map(|(_, _, routine)| routine.clone())
        .collect::<Vec<_>>();
    if selected.is_empty() {
        scored
            .into_iter()
            .take(3)
            .map(|(_, _, routine)| routine)
            .collect()
    } else {
        selected
    }
}

fn clone_directive_routine_score(
    routine: &PersonalPreferenceOperatorRoutine,
    query: &str,
    mode: &str,
    task_type: Option<&str>,
    inferred_task_phase: &str,
    current_plan_path: Option<&str>,
    current_files: &[String],
) -> f32 {
    let mut score = routine.confidence.clamp(0.0, 1.0);
    if routine_is_relevant_to_query(routine, query) {
        score += 1.0;
    }
    if mode == CLONE_MODE_PROJECT_BUILD && routine.routine_key == "product_development_loop" {
        score += 0.5;
    }
    match (inferred_task_phase, routine.routine_key.as_str()) {
        ("planning", "planning_progress_loop")
        | ("gap_review", "planning_progress_loop")
        | ("implementation", "product_development_loop")
        | ("validation", "product_development_loop")
        | ("release", "local_first_release_loop") => score += 1.0,
        ("gap_review", "product_development_loop")
        | ("planning", "product_development_loop")
        | ("implementation", "planning_progress_loop")
        | ("validation", "local_first_release_loop") => score += 0.45,
        _ => {}
    }
    if current_plan_path.is_some() && routine.routine_key == "planning_progress_loop" {
        score += 0.8;
    }
    if !current_files.is_empty() && routine.routine_key == "product_development_loop" {
        score += 0.4;
    }
    if task_type
        .map(|value| {
            let value = value.to_ascii_lowercase();
            value.contains("release") || value.contains("deploy")
        })
        .unwrap_or(false)
        && routine.routine_key == "local_first_release_loop"
    {
        score += 0.9;
    }
    score += (routine.event_support_count.min(8) as f32) * 0.05;
    score += (routine.cross_project_support_count.min(4) as f32) * 0.05;
    score
}

fn clone_directive_routine_summary(
    routine: &PersonalPreferenceOperatorRoutine,
) -> PersonalPreferenceCloneDirectiveRoutine {
    PersonalPreferenceCloneDirectiveRoutine {
        routine_id: routine.id.clone(),
        routine_key: routine.routine_key.clone(),
        title: routine.title.clone(),
        summary: routine.summary.clone(),
        purpose: routine.purpose.clone(),
        confidence: routine.confidence,
        support_count: routine.support_count,
        cross_project_support_count: routine.cross_project_support_count,
        event_support_count: routine.event_support_count,
        risk_level: routine.risk_level.clone(),
        autonomy_level: routine.autonomy_level.clone(),
        status: routine.status.clone(),
        version: routine.version,
        drift_status: routine.drift_status.clone(),
        applies_when: routine.applies_when.clone(),
    }
}

fn clone_directive_step_from_routine(
    routine: &PersonalPreferenceOperatorRoutine,
    step: &PersonalPreferenceOperatorRoutineStep,
) -> PersonalPreferenceCloneDirectiveStep {
    PersonalPreferenceCloneDirectiveStep {
        step_order: step.step_order,
        routine_id: routine.id.clone(),
        routine_key: routine.routine_key.clone(),
        step_key: step.step_key.clone(),
        title: step.title.clone(),
        instruction: step.instruction.clone(),
        required: step.required,
        approval_required: step.approval_required,
        tool_hints: step.tool_hints.clone(),
        expected_artifacts: step.expected_artifacts.clone(),
        success_check: step.success_check.clone(),
        failure_recovery: step.failure_recovery.clone(),
        evidence_claim_ids: step.evidence_claim_ids.clone(),
        event_evidence_ids: step.event_evidence_ids.clone(),
        confidence: step.confidence,
    }
}

fn clone_directive_max_risk(
    requested_risk_level: Option<&str>,
    routines: &[PersonalPreferenceOperatorRoutine],
) -> String {
    let mut risk = normalize_clone_directive_risk(requested_risk_level.unwrap_or("low"));
    for routine in routines {
        let candidate = normalize_clone_directive_risk(&routine.risk_level);
        if clone_directive_risk_rank(&candidate) > clone_directive_risk_rank(&risk) {
            risk = candidate;
        }
    }
    risk
}

fn clone_directive_risk_rank(value: &str) -> usize {
    match value {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn normalize_clone_directive_risk(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "high" | "critical" | "production" => "high".to_string(),
        "medium" | "moderate" => "medium".to_string(),
        "low" | "safe" | "minor" => "low".to_string(),
        _ => "medium".to_string(),
    }
}

fn clone_directive_approval_gates(
    routines: &[PersonalPreferenceOperatorRoutine],
    risk_level: &str,
) -> Vec<PersonalPreferenceCloneApprovalGate> {
    let mut gates = Vec::new();
    let mut seen = HashSet::new();
    for routine in routines {
        for step in &routine.steps {
            if !step.approval_required {
                continue;
            }
            let gate_key = format!("{}:{}", routine.routine_key, step.step_key);
            if !seen.insert(gate_key.clone()) {
                continue;
            }
            gates.push(PersonalPreferenceCloneApprovalGate {
                gate_key,
                routine_key: routine.routine_key.clone(),
                step_key: step.step_key.clone(),
                title: step.title.clone(),
                reason: if step.failure_recovery.trim().is_empty() {
                    "Operator routine marks this step as approval-required.".to_string()
                } else {
                    format!(
                        "Approval required before this step; recovery rule: {}",
                        step.failure_recovery
                    )
                },
                risk_level: normalize_clone_directive_risk(&routine.risk_level),
                required: true,
            });
        }
        if (risk_level == "high"
            || routine.risk_level == "high"
            || routine.autonomy_level == "approval_gated")
            && !routine.steps.iter().any(|step| step.approval_required)
        {
            let gate_key = format!("{}:routine_approval", routine.routine_key);
            if seen.insert(gate_key.clone()) {
                gates.push(PersonalPreferenceCloneApprovalGate {
                    gate_key,
                    routine_key: routine.routine_key.clone(),
                    step_key: "routine_approval".to_string(),
                    title: routine.title.clone(),
                    reason: "High-risk or approval-gated routine requires operator approval."
                        .to_string(),
                    risk_level: normalize_clone_directive_risk(&routine.risk_level),
                    required: true,
                });
            }
        }
    }
    gates
}

fn normalize_clone_directive_enforcement_level(
    requested: Option<&str>,
    risk_level: &str,
    inferred_task_phase: &str,
    approval_gates: &[PersonalPreferenceCloneApprovalGate],
) -> String {
    if let Some(requested) = requested {
        match requested.trim().to_ascii_lowercase().as_str() {
            "advisory" => return "advisory".to_string(),
            "checklist" => return "checklist".to_string(),
            "supervised" => return "supervised".to_string(),
            "autonomous" | "autonomous_low_risk" => return "autonomous_low_risk".to_string(),
            "autonomous_high_risk" => return "autonomous_high_risk".to_string(),
            _ => {}
        }
    }
    if risk_level == "high" || inferred_task_phase == "release" || !approval_gates.is_empty() {
        "supervised".to_string()
    } else if risk_level == "low" && inferred_task_phase == "planning" {
        "autonomous_low_risk".to_string()
    } else {
        "checklist".to_string()
    }
}

fn clone_directive_required_artifacts(
    required_steps: &[PersonalPreferenceCloneDirectiveStep],
    current_plan_path: Option<&str>,
) -> Vec<String> {
    let mut artifacts = Vec::new();
    let mut seen = HashSet::new();
    if let Some(path) = current_plan_path {
        push_clone_directive_unique(&mut artifacts, &mut seen, path);
    }
    for step in required_steps {
        for artifact in &step.expected_artifacts {
            push_clone_directive_unique(&mut artifacts, &mut seen, artifact);
        }
    }
    artifacts
}

fn clone_directive_validation_plan(
    required_steps: &[PersonalPreferenceCloneDirectiveStep],
) -> Vec<String> {
    let mut plan = Vec::new();
    let mut seen = HashSet::new();
    for step in required_steps {
        if !step.success_check.trim().is_empty() {
            push_clone_directive_unique(&mut plan, &mut seen, &step.success_check);
        }
    }
    if !plan.iter().any(|item| {
        let item = item.to_ascii_lowercase();
        item.contains("test") || item.contains("validate") || item.contains("check")
    }) {
        push_clone_directive_unique(
            &mut plan,
            &mut seen,
            "Run targeted validation and record evidence before final response.",
        );
    }
    push_clone_directive_unique(
        &mut plan,
        &mut seen,
        "Compare completed work against this clone directive before final response.",
    );
    plan
}

fn clone_directive_memory_to_load(
    agent_id: Option<&str>,
    pack: &PersonalPreferenceCloneContextPack,
    required_steps: &[PersonalPreferenceCloneDirectiveStep],
) -> Vec<String> {
    let mut memory = Vec::new();
    let mut seen = HashSet::new();
    push_clone_directive_unique(
        &mut memory,
        &mut seen,
        format!(
            "profile_memory:{}",
            agent_id.unwrap_or("active_agent_profile")
        ),
    );
    push_clone_directive_unique(
        &mut memory,
        &mut seen,
        format!("repo_memory:{}", pack.query),
    );
    push_clone_directive_unique(
        &mut memory,
        &mut seen,
        format!("clone_context_pack:{}", pack.mode),
    );
    for item in &pack.items {
        push_clone_directive_unique(&mut memory, &mut seen, format!("section:{}", item.section));
    }
    for trace in &pack.trace {
        push_clone_directive_unique(&mut memory, &mut seen, format!("claim:{}", trace.claim_id));
        if memory.len() >= 48 {
            return memory;
        }
    }
    for step in required_steps {
        for claim_id in &step.evidence_claim_ids {
            push_clone_directive_unique(&mut memory, &mut seen, format!("claim:{claim_id}"));
            if memory.len() >= 48 {
                return memory;
            }
        }
        for event_id in &step.event_evidence_ids {
            push_clone_directive_unique(
                &mut memory,
                &mut seen,
                format!("operator_event:{event_id}"),
            );
            if memory.len() >= 48 {
                return memory;
            }
        }
    }
    memory
}

fn clone_directive_stop_conditions(
    risk_level: &str,
    approval_gates: &[PersonalPreferenceCloneApprovalGate],
) -> Vec<String> {
    let mut conditions = vec![
        "Stop if repo truth contradicts this clone directive.".to_string(),
        "Stop if required artifacts or evidence cannot be found.".to_string(),
        "Stop if validation fails after one repair attempt and no safe fix is clear.".to_string(),
    ];
    if risk_level == "high" || !approval_gates.is_empty() {
        conditions.push(
            "Stop before deploy, destructive, billing, credential, or production actions unless explicit operator approval is present."
                .to_string(),
        );
    }
    conditions
}

fn clone_directive_avoidances() -> Vec<String> {
    vec![
        "Do not treat clone inference as technical repo truth.".to_string(),
        "Do not include raw transcripts or sensitive values in directive output.".to_string(),
        "Do not skip progress, plan, or validation steps for multi-step work.".to_string(),
        "Do not run destructive or production actions without explicit approval.".to_string(),
    ]
}

fn clone_directive_confidence(
    selected_routines: &[PersonalPreferenceOperatorRoutine],
    required_steps: &[PersonalPreferenceCloneDirectiveStep],
    pack_item_count: usize,
) -> f32 {
    let routine_confidence = if selected_routines.is_empty() {
        0.0
    } else {
        selected_routines
            .iter()
            .map(|routine| routine.confidence)
            .sum::<f32>()
            / selected_routines.len() as f32
    };
    let step_count = required_steps.len().max(1) as f32;
    let claim_coverage = required_steps
        .iter()
        .filter(|step| !step.evidence_claim_ids.is_empty())
        .count() as f32
        / step_count;
    let event_coverage = required_steps
        .iter()
        .filter(|step| !step.event_evidence_ids.is_empty())
        .count() as f32
        / step_count;
    let pack_boost = ((pack_item_count.min(8) as f32) / 8.0) * 0.1;
    (routine_confidence * 0.65 + claim_coverage * 0.12 + event_coverage * 0.13 + pack_boost)
        .clamp(0.0, 1.0)
}

fn clone_directive_evidence_summary(
    selected_routines: &[PersonalPreferenceOperatorRoutine],
    required_steps: &[PersonalPreferenceCloneDirectiveStep],
    pack_item_count: usize,
) -> String {
    let claim_ids = required_steps
        .iter()
        .flat_map(|step| step.evidence_claim_ids.iter())
        .collect::<HashSet<_>>()
        .len();
    let event_ids = required_steps
        .iter()
        .flat_map(|step| step.event_evidence_ids.iter())
        .collect::<HashSet<_>>()
        .len();
    format!(
        "Selected {} routine(s), {} required step(s), {} claim evidence id(s), {} operator event evidence id(s), and {} clone-pack item(s).",
        selected_routines.len(),
        required_steps.len(),
        claim_ids,
        event_ids,
        pack_item_count
    )
}

fn push_clone_directive_unique(
    target: &mut Vec<String>,
    seen: &mut HashSet<String>,
    value: impl AsRef<str>,
) {
    let value = value.as_ref().trim();
    if value.is_empty() || !seen.insert(value.to_string()) {
        return;
    }
    target.push(value.to_string());
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}
