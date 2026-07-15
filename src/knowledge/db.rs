use crate::config::MemoryConversationGraphConfig;
use crate::knowledge::entity_registry::{normalize_entity_name, normalize_relation_name};
use crate::knowledge::graph::score_fact_match;
use crate::knowledge::ontology::{
    KnowledgeOntology, RelationCardinality, ValidatedKnowledgeCandidate,
};
use crate::knowledge::timeline::fact_timeline_ts;
use crate::knowledge::types::{
    KnowledgeClearResult, KnowledgeEdgeDeleteResult, KnowledgeEdgeEvidenceRecord,
    KnowledgeEdgeSearchResult, KnowledgeEntityLinkRecord, KnowledgeEntityLinksResult,
    KnowledgeEntityRecord, KnowledgeEpisodeDeleteResult, KnowledgeEpisodeDetailResult,
    KnowledgeEpisodeRecord, KnowledgeEpisodeSearchResult, KnowledgeFactCandidate,
    KnowledgeFactRecord, KnowledgeGraphCandidate, KnowledgeGraphEdgeRecord,
    KnowledgeNeighborhoodResult, KnowledgeNodeSearchResult, KnowledgeQueryResult,
    KnowledgeRebuildResult, KnowledgeTimelineEvent, KnowledgeTimelineResult,
};
use anyhow::{Context, Result};
use fs4::FileExt;
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::Digest;
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::warn;
use uuid::Uuid;

const KNOWLEDGE_SCHEMA_VERSION: u32 = 2;

#[derive(Clone)]
pub struct KnowledgeStore {
    path: PathBuf,
    lock_path: PathBuf,
    lock: Arc<Mutex<()>>,
}

impl KnowledgeStore {
    pub fn new(state_dir: &Path) -> Self {
        let repo_root = crate::memory::repo_state_root_from_state_dir(state_dir);
        let _ = crate::memory::ensure_repo_state_dir(&repo_root);
        let lock_dir = crate::memory::locks_dir_from_state_dir(state_dir);
        let _ = crate::state_layout::ensure_state_dir_secure(&lock_dir);
        Self::from_paths(
            crate::knowledge::knowledge_path(state_dir),
            crate::knowledge::knowledge_lock_path(state_dir),
        )
    }

    pub fn for_namespace(base_state_dir: &Path, namespace: &str) -> Self {
        let layout = crate::state_layout::StateLayout::new(base_state_dir.to_path_buf());
        let _ = layout.ensure_global_dirs();
        Self::from_paths(
            crate::knowledge::knowledge_namespace_path(base_state_dir, namespace),
            crate::knowledge::knowledge_namespace_lock_path(base_state_dir, namespace),
        )
    }

    pub fn from_paths(path: PathBuf, lock_path: PathBuf) -> Self {
        Self {
            path,
            lock_path,
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn check_access(&self) -> Result<()> {
        let _guard = self.lock.lock();
        let _file_lock = self.lock_exclusive()?;
        let _ = self.open_connection()?;
        Ok(())
    }

    pub fn store_candidates(
        &self,
        session_id: &str,
        created_at_ms: i64,
        candidates: &[KnowledgeFactCandidate],
    ) -> Result<Vec<KnowledgeFactRecord>> {
        self.store_graph_candidates_with_graph_config(session_id, created_at_ms, candidates, None)
    }

    pub fn store_candidates_with_graph_config(
        &self,
        session_id: &str,
        created_at_ms: i64,
        candidates: &[KnowledgeFactCandidate],
        graph_config: Option<&MemoryConversationGraphConfig>,
    ) -> Result<Vec<KnowledgeFactRecord>> {
        self.store_graph_candidates_with_graph_config(
            session_id,
            created_at_ms,
            candidates,
            graph_config,
        )
    }

    pub fn store_graph_candidates(
        &self,
        session_id: &str,
        created_at_ms: i64,
        candidates: &[KnowledgeGraphCandidate],
    ) -> Result<Vec<KnowledgeFactRecord>> {
        self.store_graph_candidates_with_graph_config(session_id, created_at_ms, candidates, None)
    }

    pub fn store_graph_candidates_with_graph_config(
        &self,
        session_id: &str,
        created_at_ms: i64,
        candidates: &[KnowledgeGraphCandidate],
        graph_config: Option<&MemoryConversationGraphConfig>,
    ) -> Result<Vec<KnowledgeFactRecord>> {
        let session_id = session_id.trim();
        if session_id.is_empty() {
            anyhow::bail!("session_id must not be empty");
        }
        if candidates.is_empty() {
            return Ok(Vec::new());
        }
        let ontology = KnowledgeOntology::from_graph_config(graph_config);

        let _guard = self.lock.lock();
        let _file_lock = self.lock_exclusive()?;
        let mut conn = self.open_connection()?;
        let tx = conn.transaction()?;
        let mut facts = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let Some(fact) =
                store_fact_candidate(&tx, session_id, created_at_ms, candidate, &ontology)?
            else {
                continue;
            };
            facts.push(fact);
        }
        tx.commit()?;
        Ok(facts)
    }

    pub fn query_facts(
        &self,
        query: &str,
        relation: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<KnowledgeQueryResult> {
        let query = query.trim();
        if query.is_empty() {
            anyhow::bail!("query must not be empty");
        }
        let limit = limit.max(1);
        let normalized_query = normalize_entity_name(query);

        let _guard = self.lock.lock();
        let _file_lock = self.lock_shared()?;
        let conn = self.open_connection()?;
        let matched_entities = load_entities(&conn, &normalized_query, None, limit, offset)?;
        let relation = relation
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(normalize_relation_name);
        let mut facts = load_facts_for_query(&conn, &normalized_query, relation.as_deref())?;
        facts.sort_by(|left, right| {
            score_fact_match(right, &normalized_query)
                .cmp(&score_fact_match(left, &normalized_query))
                .then_with(|| right.updated_at_ms.cmp(&left.updated_at_ms))
                .then_with(|| left.fact_id.cmp(&right.fact_id))
        });
        let total = facts.len();
        let facts = facts
            .into_iter()
            .skip(offset)
            .take(limit)
            .collect::<Vec<_>>();
        Ok(KnowledgeQueryResult {
            query: query.to_string(),
            total,
            limit,
            offset,
            matched_entities,
            facts,
        })
    }

    pub fn search_nodes(
        &self,
        query: &str,
        entity_type: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<KnowledgeNodeSearchResult> {
        let query = query.trim();
        if query.is_empty() {
            anyhow::bail!("query must not be empty");
        }
        let limit = limit.max(1);
        let normalized_query = normalize_entity_name(query);
        let entity_type = entity_type
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);

        let _guard = self.lock.lock();
        let _file_lock = self.lock_shared()?;
        let conn = self.open_connection()?;
        let total = count_entities(&conn, &normalized_query, entity_type.as_deref())?;
        let nodes = load_entities(
            &conn,
            &normalized_query,
            entity_type.as_deref(),
            limit,
            offset,
        )?;
        Ok(KnowledgeNodeSearchResult {
            query: query.to_string(),
            total,
            limit,
            offset,
            nodes,
        })
    }

    pub fn search_edges(
        &self,
        query: &str,
        relation: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<KnowledgeEdgeSearchResult> {
        let query = query.trim();
        if query.is_empty() {
            anyhow::bail!("query must not be empty");
        }
        let limit = limit.max(1);
        let normalized_query = normalize_entity_name(query);
        let relation = relation
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(normalize_relation_name);

        let _guard = self.lock.lock();
        let _file_lock = self.lock_shared()?;
        let conn = self.open_connection()?;
        let total = count_edges(&conn, &normalized_query, relation.as_deref())?;
        let edges =
            load_edges_for_search(&conn, &normalized_query, relation.as_deref(), limit, offset)?;
        Ok(KnowledgeEdgeSearchResult {
            query: query.to_string(),
            total,
            limit,
            offset,
            edges,
        })
    }

    pub fn neighborhood_for_entity(
        &self,
        entity: &str,
        relation: Option<&str>,
        limit: usize,
    ) -> Result<KnowledgeNeighborhoodResult> {
        let entity = entity.trim();
        if entity.is_empty() {
            anyhow::bail!("entity must not be empty");
        }
        let normalized_entity = normalize_entity_name(entity);
        let relation = relation
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(normalize_relation_name);
        let limit = limit.max(1);

        let _guard = self.lock.lock();
        let _file_lock = self.lock_shared()?;
        let conn = self.open_connection()?;
        let matched_entities = load_entities(&conn, &normalized_entity, None, limit, 0)?;
        let entity_ids = matched_entities
            .iter()
            .map(|item| item.entity_id.clone())
            .collect::<HashSet<_>>();
        let total =
            count_neighborhood_edges(&conn, &normalized_entity, relation.as_deref(), &entity_ids)?;
        let edges = load_neighborhood_edges(
            &conn,
            &normalized_entity,
            relation.as_deref(),
            &entity_ids,
            limit,
        )?;
        Ok(KnowledgeNeighborhoodResult {
            entity: entity.to_string(),
            total,
            limit,
            matched_entities,
            edges,
        })
    }

    pub fn entity_links_for_entity(
        &self,
        entity: &str,
        link_type: Option<&str>,
        limit: usize,
    ) -> Result<KnowledgeEntityLinksResult> {
        let entity = entity.trim();
        if entity.is_empty() {
            anyhow::bail!("entity must not be empty");
        }
        let normalized_entity = normalize_entity_name(entity);
        let link_type = link_type
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(normalize_relation_name);
        let limit = limit.max(1);

        let _guard = self.lock.lock();
        let _file_lock = self.lock_shared()?;
        let conn = self.open_connection()?;
        let matched_entities = load_entities(&conn, &normalized_entity, None, limit.max(1), 0)?;
        let mut total = 0usize;
        let mut seen = HashSet::new();
        let mut links = Vec::new();
        for item in &matched_entities {
            total += count_entity_links(&conn, &item.entity_id, link_type.as_deref())?;
            for link in load_entity_links(&conn, &item.entity_id, link_type.as_deref(), limit)? {
                if seen.insert(link.link_id.clone()) {
                    links.push(link);
                }
            }
        }
        links.sort_by(|left, right| {
            right
                .updated_at_ms
                .cmp(&left.updated_at_ms)
                .then_with(|| left.link_id.cmp(&right.link_id))
        });
        links.truncate(limit);
        Ok(KnowledgeEntityLinksResult {
            entity: entity.to_string(),
            total,
            limit,
            matched_entities,
            links,
        })
    }

    pub fn search_episodes(
        &self,
        query: &str,
        source_type: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<KnowledgeEpisodeSearchResult> {
        let query = query.trim();
        if query.is_empty() {
            anyhow::bail!("query must not be empty");
        }
        let limit = limit.max(1);
        let normalized_query = query.to_ascii_lowercase();
        let source_type = source_type
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);

        let _guard = self.lock.lock();
        let _file_lock = self.lock_shared()?;
        let conn = self.open_connection()?;
        let total = count_episodes(&conn, &normalized_query, source_type.as_deref())?;
        let episodes = load_episodes(
            &conn,
            &normalized_query,
            source_type.as_deref(),
            limit,
            offset,
        )?;
        Ok(KnowledgeEpisodeSearchResult {
            query: query.to_string(),
            total,
            limit,
            offset,
            episodes,
        })
    }

    pub fn episode_details(
        &self,
        episode_id: &str,
        limit: usize,
    ) -> Result<Option<KnowledgeEpisodeDetailResult>> {
        let episode_id = episode_id.trim();
        if episode_id.is_empty() {
            anyhow::bail!("episode_id must not be empty");
        }
        let limit = limit.max(1);

        let _guard = self.lock.lock();
        let _file_lock = self.lock_shared()?;
        let conn = self.open_connection()?;
        let Some(episode) = load_episode_record(&conn, episode_id)? else {
            return Ok(None);
        };
        let total_edges = count_edges_for_episode(&conn, episode_id)?;
        let edges = load_edges_for_episode(&conn, episode_id, limit)?;
        let edge_ids = edges
            .iter()
            .map(|edge| edge.edge_id.clone())
            .collect::<HashSet<_>>();
        let evidence = load_evidence_for_episode(&conn, episode_id, &edge_ids)?;
        Ok(Some(KnowledgeEpisodeDetailResult {
            episode,
            total_edges,
            limit,
            edges,
            evidence,
        }))
    }

    pub fn episode_records(
        &self,
        episode_ids: &[String],
        limit: usize,
    ) -> Result<Vec<KnowledgeEpisodeRecord>> {
        let limit = limit.max(1);
        let mut ordered_ids = Vec::new();
        let mut seen = HashSet::new();
        for episode_id in episode_ids {
            let trimmed = episode_id.trim();
            if trimmed.is_empty() || !seen.insert(trimmed.to_string()) {
                continue;
            }
            ordered_ids.push(trimmed.to_string());
            if ordered_ids.len() >= limit {
                break;
            }
        }
        if ordered_ids.is_empty() {
            return Ok(Vec::new());
        }

        let _guard = self.lock.lock();
        let _file_lock = self.lock_shared()?;
        let conn = self.open_connection()?;
        let mut episodes = Vec::new();
        for episode_id in ordered_ids {
            if let Some(episode) = load_episode_record(&conn, &episode_id)? {
                episodes.push(episode);
            }
        }
        Ok(episodes)
    }

    pub fn episode_records_for_sources(
        &self,
        source_type: &str,
        source_ids: &[String],
        limit: usize,
    ) -> Result<Vec<KnowledgeEpisodeRecord>> {
        let source_type = normalize_relation_name(source_type);
        if source_type.is_empty() {
            return Ok(Vec::new());
        }
        let limit = limit.max(1);
        let mut ordered_ids = Vec::new();
        let mut seen = HashSet::new();
        for source_id in source_ids {
            let trimmed = source_id.trim();
            if trimmed.is_empty() || !seen.insert(trimmed.to_string()) {
                continue;
            }
            ordered_ids.push(trimmed.to_string());
            if ordered_ids.len() >= limit {
                break;
            }
        }
        if ordered_ids.is_empty() {
            return Ok(Vec::new());
        }

        let _guard = self.lock.lock();
        let _file_lock = self.lock_shared()?;
        let conn = self.open_connection()?;
        let mut episodes = Vec::new();
        for source_id in ordered_ids {
            if let Some(episode) = load_episode_record_for_source(&conn, &source_type, &source_id)?
            {
                episodes.push(episode);
            }
        }
        Ok(episodes)
    }

    pub fn record_episode_note(
        &self,
        source_type: &str,
        source_id: &str,
        session_id: Option<&str>,
        summary: &str,
        metadata: Value,
        happened_at_ms: i64,
    ) -> Result<Option<KnowledgeEpisodeRecord>> {
        let source_type = normalize_relation_name(source_type);
        let source_id = cleaned_text(source_id);
        let summary = cleaned_text(summary);
        if source_type.is_empty() || source_id.is_empty() || summary.is_empty() {
            return Ok(None);
        }

        let _guard = self.lock.lock();
        let _file_lock = self.lock_exclusive()?;
        let mut conn = self.open_connection()?;
        let tx = conn.transaction()?;
        let episode_id = upsert_episode_record(
            &tx,
            &source_type,
            &source_id,
            session_id,
            &summary,
            metadata,
            happened_at_ms,
        )?;
        let episode = load_episode_record(&tx, &episode_id)?;
        tx.commit()?;
        Ok(episode)
    }

    pub fn timeline_for_entity(
        &self,
        entity: &str,
        relation: Option<&str>,
        limit: usize,
    ) -> Result<KnowledgeTimelineResult> {
        let entity = entity.trim();
        if entity.is_empty() {
            anyhow::bail!("entity must not be empty");
        }
        let normalized_entity = normalize_entity_name(entity);
        let relation = relation
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(normalize_relation_name);

        let _guard = self.lock.lock();
        let _file_lock = self.lock_shared()?;
        let conn = self.open_connection()?;
        let matched_entities = load_entities(&conn, &normalized_entity, None, limit.max(1), 0)?;
        let entity_ids = matched_entities
            .iter()
            .map(|item| item.entity_id.clone())
            .collect::<HashSet<_>>();
        let mut facts =
            load_facts_for_timeline(&conn, &normalized_entity, relation.as_deref(), &entity_ids)?;
        facts.sort_by(|left, right| {
            fact_timeline_ts(left)
                .cmp(&fact_timeline_ts(right))
                .then_with(|| left.fact_id.cmp(&right.fact_id))
        });
        let total = facts.len();
        let events = facts
            .into_iter()
            .take(limit.max(1))
            .map(|fact| {
                let occurred_at_ms = fact_timeline_ts(&fact);
                KnowledgeTimelineEvent {
                    fact_id: fact.fact_id,
                    session_id: fact.session_id,
                    subject: fact.subject,
                    relation: fact.relation,
                    object_text: fact.object_text,
                    summary: fact.summary,
                    occurred_at_ms,
                    valid_from_ms: fact.valid_from_ms,
                    valid_to_ms: fact.valid_to_ms,
                    invalidated_at_ms: fact.invalidated_at_ms,
                }
            })
            .collect::<Vec<_>>();
        Ok(KnowledgeTimelineResult {
            entity: entity.to_string(),
            total,
            limit: limit.max(1),
            matched_entities,
            events,
        })
    }

    pub fn facts_for_session(&self, session_id: &str) -> Result<Vec<KnowledgeFactRecord>> {
        let session_id = session_id.trim();
        if session_id.is_empty() {
            anyhow::bail!("session_id must not be empty");
        }
        let _guard = self.lock.lock();
        let _file_lock = self.lock_shared()?;
        let conn = self.open_connection()?;
        load_facts_by_session(&conn, session_id)
    }

    pub fn delete_facts_for_session(&self, session_id: &str) -> Result<usize> {
        self.delete_facts_for_sessions(&[session_id.to_string()])
    }

    pub fn delete_facts_for_sessions(&self, session_ids: &[String]) -> Result<usize> {
        let cleaned = session_ids
            .iter()
            .map(|item| item.trim())
            .filter(|item| !item.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        if cleaned.is_empty() {
            return Ok(0);
        }

        let _guard = self.lock.lock();
        let _file_lock = self.lock_exclusive()?;
        let mut conn = self.open_connection()?;
        let tx = conn.transaction()?;
        let mut deleted = 0usize;
        for session_id in &cleaned {
            let mut edge_stmt =
                tx.prepare("SELECT id, episode_id FROM knowledge_edges WHERE session_id = ?1")?;
            let edge_rows = edge_stmt.query_map(params![session_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
            })?;
            let edge_records = edge_rows.collect::<rusqlite::Result<Vec<_>>>()?;
            let episode_ids = edge_records
                .iter()
                .filter_map(|(_, episode_id)| episode_id.clone())
                .collect::<HashSet<_>>();
            for (edge_id, _) in &edge_records {
                tx.execute(
                    "DELETE FROM knowledge_edge_evidence WHERE edge_id = ?1",
                    params![edge_id],
                )?;
                tx.execute(
                    "DELETE FROM knowledge_edge_invalidations WHERE edge_id = ?1",
                    params![edge_id],
                )?;
                delete_entity_links_for_edge(&tx, edge_id)?;
            }
            tx.execute(
                "DELETE FROM knowledge_edges WHERE session_id = ?1",
                params![session_id],
            )?;
            for episode_id in episode_ids {
                tx.execute(
                    "DELETE FROM knowledge_edge_evidence WHERE episode_id = ?1",
                    params![&episode_id],
                )?;
                tx.execute(
                    "DELETE FROM knowledge_episodes WHERE id = ?1",
                    params![&episode_id],
                )?;
            }
            deleted += tx.execute(
                "DELETE FROM knowledge_facts WHERE session_id = ?1",
                params![session_id],
            )?;
        }
        gc_orphaned_entities(&tx)?;
        tx.commit()?;
        Ok(deleted)
    }

    pub fn delete_edge(&self, edge_id: &str) -> Result<KnowledgeEdgeDeleteResult> {
        let edge_id = edge_id.trim();
        if edge_id.is_empty() {
            anyhow::bail!("edge_id must not be empty");
        }

        let _guard = self.lock.lock();
        let _file_lock = self.lock_exclusive()?;
        let mut conn = self.open_connection()?;
        let tx = conn.transaction()?;
        let Some((fact_id, _episode_id)) = tx
            .query_row(
                "SELECT fact_id, episode_id FROM knowledge_edges WHERE id = ?1 LIMIT 1",
                params![edge_id],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                    ))
                },
            )
            .optional()?
        else {
            return Ok(KnowledgeEdgeDeleteResult {
                edge_id: edge_id.to_string(),
                deleted: false,
                deleted_evidence: 0,
                deleted_invalidations: 0,
                deleted_entity_links: 0,
                deleted_fact_id: None,
            });
        };

        let deleted_evidence = tx.execute(
            "DELETE FROM knowledge_edge_evidence WHERE edge_id = ?1",
            params![edge_id],
        )?;
        let deleted_invalidations = tx.execute(
            "DELETE FROM knowledge_edge_invalidations WHERE edge_id = ?1",
            params![edge_id],
        )?;
        let deleted_entity_links = delete_entity_links_for_edge(&tx, edge_id)?;
        tx.execute(
            "DELETE FROM knowledge_edges WHERE id = ?1",
            params![edge_id],
        )?;
        let deleted_fact_id = if let Some(fact_id) = fact_id {
            tx.execute(
                "DELETE FROM knowledge_facts WHERE id = ?1",
                params![&fact_id],
            )?;
            Some(fact_id)
        } else {
            None
        };
        gc_orphaned_entities(&tx)?;
        tx.commit()?;
        Ok(KnowledgeEdgeDeleteResult {
            edge_id: edge_id.to_string(),
            deleted: true,
            deleted_evidence,
            deleted_invalidations,
            deleted_entity_links,
            deleted_fact_id,
        })
    }

    pub fn delete_episode(&self, episode_id: &str) -> Result<KnowledgeEpisodeDeleteResult> {
        let episode_id = episode_id.trim();
        if episode_id.is_empty() {
            anyhow::bail!("episode_id must not be empty");
        }

        let _guard = self.lock.lock();
        let _file_lock = self.lock_exclusive()?;
        let mut conn = self.open_connection()?;
        let tx = conn.transaction()?;
        let Some(()) = tx
            .query_row(
                "SELECT 1 FROM knowledge_episodes WHERE id = ?1 LIMIT 1",
                params![episode_id],
                |_| Ok(()),
            )
            .optional()?
        else {
            return Ok(KnowledgeEpisodeDeleteResult {
                episode_id: episode_id.to_string(),
                deleted: false,
                deleted_edges: 0,
                deleted_facts: 0,
                deleted_evidence: 0,
                deleted_invalidations: 0,
                deleted_entity_links: 0,
            });
        };

        let mut edge_stmt = tx.prepare(
            "SELECT id, fact_id FROM knowledge_edges WHERE episode_id = ?1 ORDER BY id ASC",
        )?;
        let edge_rows = edge_stmt.query_map(params![episode_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
        })?;
        let edge_records = edge_rows.collect::<rusqlite::Result<Vec<_>>>()?;
        drop(edge_stmt);
        let mut deleted_facts = 0usize;
        let mut deleted_invalidations = 0usize;
        let deleted_entity_links = delete_entity_links_for_episode(&tx, episode_id)?;
        for (edge_id, fact_id) in &edge_records {
            deleted_invalidations += tx.execute(
                "DELETE FROM knowledge_edge_invalidations WHERE edge_id = ?1",
                params![edge_id],
            )?;
            if let Some(fact_id) = fact_id {
                deleted_facts += tx.execute(
                    "DELETE FROM knowledge_facts WHERE id = ?1",
                    params![fact_id],
                )?;
            }
        }
        let deleted_evidence = tx.execute(
            "DELETE FROM knowledge_edge_evidence WHERE episode_id = ?1",
            params![episode_id],
        )?;
        let deleted_edges = tx.execute(
            "DELETE FROM knowledge_edges WHERE episode_id = ?1",
            params![episode_id],
        )?;
        tx.execute(
            "DELETE FROM knowledge_episodes WHERE id = ?1",
            params![episode_id],
        )?;
        gc_orphaned_entities(&tx)?;
        tx.commit()?;
        Ok(KnowledgeEpisodeDeleteResult {
            episode_id: episode_id.to_string(),
            deleted: true,
            deleted_edges,
            deleted_facts,
            deleted_evidence,
            deleted_invalidations,
            deleted_entity_links,
        })
    }

    pub fn rebuild(&self) -> Result<KnowledgeRebuildResult> {
        let _guard = self.lock.lock();
        let _file_lock = self.lock_exclusive()?;
        let mut conn = self.open_connection()?;
        let tx = conn.transaction()?;
        let orphan_links_deleted = tx.execute(
            "DELETE FROM knowledge_entity_links
             WHERE entity_id NOT IN (SELECT id FROM knowledge_entities)",
            [],
        )?;
        let entity_self_links_projected = rebuild_entity_self_links(&tx)?;
        let relation_links_projected = rebuild_relation_entity_links(&tx)?;
        tx.execute_batch("REINDEX; ANALYZE;")?;
        tx.commit()?;
        Ok(KnowledgeRebuildResult {
            rebuilt: true,
            entity_self_links_projected,
            relation_links_projected,
            orphan_links_deleted,
        })
    }

    pub fn clear(&self) -> Result<KnowledgeClearResult> {
        let _guard = self.lock.lock();
        let _file_lock = self.lock_exclusive()?;
        let mut conn = self.open_connection()?;
        let tx = conn.transaction()?;

        let deleted_aliases = tx.execute("DELETE FROM knowledge_aliases", [])?;
        let deleted_evidence = tx.execute("DELETE FROM knowledge_edge_evidence", [])?;
        let deleted_invalidations = tx.execute("DELETE FROM knowledge_edge_invalidations", [])?;
        let deleted_links = tx.execute("DELETE FROM knowledge_entity_links", [])?;
        let deleted_edges = tx.execute("DELETE FROM knowledge_edges", [])?;
        let deleted_episodes = tx.execute("DELETE FROM knowledge_episodes", [])?;
        let deleted_facts = tx.execute("DELETE FROM knowledge_facts", [])?;
        let deleted_entities = tx.execute("DELETE FROM knowledge_entities", [])?;
        tx.commit()?;
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;")?;

        Ok(KnowledgeClearResult {
            cleared: true,
            deleted_entities,
            deleted_aliases,
            deleted_facts,
            deleted_episodes,
            deleted_edges,
            deleted_evidence,
            deleted_invalidations,
            deleted_links,
        })
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

    fn open_connection(&self) -> Result<Connection> {
        if let Some(parent) = self.path.parent() {
            crate::state_layout::ensure_state_dir_secure(parent)?;
        }
        if let Some(parent) = self.lock_path.parent() {
            crate::state_layout::ensure_state_dir_secure(parent)?;
        }
        let conn = crate::sqlite::open_rw_create_full_mutex(&self.path, "knowledge")?;
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
         CREATE TABLE IF NOT EXISTS knowledge_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS knowledge_entities (
            id TEXT PRIMARY KEY,
            canonical_name TEXT NOT NULL,
            normalized_name TEXT NOT NULL UNIQUE,
            entity_type TEXT NOT NULL,
            aliases_json TEXT NOT NULL,
            aliases_text TEXT NOT NULL,
            metadata TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS knowledge_aliases (
            normalized_alias TEXT NOT NULL,
            alias TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            PRIMARY KEY(normalized_alias, entity_id)
         );
         CREATE INDEX IF NOT EXISTS knowledge_aliases_entity_idx
             ON knowledge_aliases(entity_id, normalized_alias);
         CREATE TABLE IF NOT EXISTS knowledge_facts (
            id TEXT PRIMARY KEY,
            fact_key TEXT NOT NULL UNIQUE,
            session_id TEXT,
            subject_entity_id TEXT,
            subject_name TEXT NOT NULL,
            subject_aliases_json TEXT NOT NULL,
            subject_aliases_text TEXT NOT NULL,
            relation TEXT NOT NULL,
            object_entity_id TEXT,
            object_name TEXT,
            object_aliases_json TEXT NOT NULL,
            object_aliases_text TEXT NOT NULL,
            object_text TEXT NOT NULL,
            summary TEXT NOT NULL,
            category TEXT NOT NULL,
            confidence TEXT NOT NULL,
            provenance_json TEXT NOT NULL,
            entity_hints_json TEXT NOT NULL,
            entity_hints_text TEXT NOT NULL,
            valid_from_ms INTEGER,
            valid_to_ms INTEGER,
            invalidated_at_ms INTEGER,
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS knowledge_facts_session_idx
             ON knowledge_facts(session_id, updated_at_ms DESC, id);
         CREATE INDEX IF NOT EXISTS knowledge_facts_subject_idx
             ON knowledge_facts(subject_name, updated_at_ms DESC, id);
         CREATE INDEX IF NOT EXISTS knowledge_facts_object_idx
             ON knowledge_facts(object_name, updated_at_ms DESC, id);
         CREATE INDEX IF NOT EXISTS knowledge_facts_relation_idx
             ON knowledge_facts(relation, updated_at_ms DESC, id);
         CREATE TABLE IF NOT EXISTS knowledge_episodes (
            id TEXT PRIMARY KEY,
            session_id TEXT,
            source_type TEXT NOT NULL,
            source_id TEXT NOT NULL,
            summary TEXT NOT NULL,
            happened_at_ms INTEGER NOT NULL,
            metadata TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL
         );
         CREATE UNIQUE INDEX IF NOT EXISTS knowledge_episodes_source_idx
             ON knowledge_episodes(source_type, source_id);
         CREATE INDEX IF NOT EXISTS knowledge_episodes_session_idx
             ON knowledge_episodes(session_id, happened_at_ms DESC, id);
         CREATE TABLE IF NOT EXISTS knowledge_edges (
            id TEXT PRIMARY KEY,
            edge_key TEXT NOT NULL UNIQUE,
            fact_id TEXT,
            episode_id TEXT,
            session_id TEXT,
            subject_entity_id TEXT,
            subject_name TEXT NOT NULL,
            relation TEXT NOT NULL,
            object_entity_id TEXT,
            object_name TEXT,
            object_text TEXT NOT NULL,
            summary TEXT NOT NULL,
            category TEXT NOT NULL,
            confidence TEXT NOT NULL,
            valid_from_ms INTEGER,
            valid_to_ms INTEGER,
            invalidated_at_ms INTEGER,
            metadata TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS knowledge_edges_subject_idx
             ON knowledge_edges(subject_entity_id, updated_at_ms DESC, id);
         CREATE INDEX IF NOT EXISTS knowledge_edges_object_idx
             ON knowledge_edges(object_entity_id, updated_at_ms DESC, id);
         CREATE INDEX IF NOT EXISTS knowledge_edges_relation_idx
             ON knowledge_edges(relation, updated_at_ms DESC, id);
         CREATE INDEX IF NOT EXISTS knowledge_edges_episode_idx
             ON knowledge_edges(episode_id, updated_at_ms DESC, id);
         CREATE INDEX IF NOT EXISTS knowledge_edges_session_idx
             ON knowledge_edges(session_id, updated_at_ms DESC, id);
         CREATE TABLE IF NOT EXISTS knowledge_edge_evidence (
            id TEXT PRIMARY KEY,
            edge_id TEXT NOT NULL,
            episode_id TEXT NOT NULL,
            session_id TEXT,
            source_role TEXT,
            source_ordinal INTEGER,
            snippet TEXT NOT NULL,
            metadata TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL
         );
         CREATE UNIQUE INDEX IF NOT EXISTS knowledge_edge_evidence_dedupe_idx
             ON knowledge_edge_evidence(edge_id, episode_id, session_id, source_role, source_ordinal);
         CREATE INDEX IF NOT EXISTS knowledge_edge_evidence_edge_idx
             ON knowledge_edge_evidence(edge_id, created_at_ms DESC, id);
         CREATE TABLE IF NOT EXISTS knowledge_edge_invalidations (
            id TEXT PRIMARY KEY,
            edge_id TEXT NOT NULL,
            invalidated_at_ms INTEGER NOT NULL,
            reason TEXT NOT NULL,
            replacement_edge_id TEXT,
            metadata TEXT NOT NULL
         );
         CREATE INDEX IF NOT EXISTS knowledge_edge_invalidations_edge_idx
             ON knowledge_edge_invalidations(edge_id, invalidated_at_ms DESC, id);
         CREATE TABLE IF NOT EXISTS knowledge_entity_links (
            id TEXT PRIMARY KEY,
            entity_id TEXT NOT NULL,
            link_type TEXT NOT NULL,
            target TEXT NOT NULL,
            metadata TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL,
            UNIQUE(entity_id, link_type, target)
         );
         CREATE INDEX IF NOT EXISTS knowledge_entity_links_entity_idx
             ON knowledge_entity_links(entity_id, updated_at_ms DESC, id);",
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO knowledge_meta(key, value) VALUES('schema_version', ?1)",
        params![KNOWLEDGE_SCHEMA_VERSION.to_string()],
    )?;
    Ok(())
}

fn store_fact_candidate(
    conn: &Connection,
    session_id: &str,
    created_at_ms: i64,
    candidate: &KnowledgeFactCandidate,
    ontology: &KnowledgeOntology,
) -> Result<Option<KnowledgeFactRecord>> {
    let subject = cleaned_text(&candidate.subject);
    if subject.is_empty() {
        anyhow::bail!("knowledge fact subject must not be empty");
    }
    let object_text = cleaned_text(&candidate.object_text);
    if object_text.is_empty() {
        anyhow::bail!("knowledge fact object_text must not be empty");
    }
    let Some(validated) = ontology.validate_candidate(candidate, &subject, &object_text) else {
        warn!(
            target: "docdexd",
            relation = %candidate.relation,
            category = %candidate.category,
            "skipping knowledge fact candidate rejected by graph ontology"
        );
        return Ok(None);
    };
    let relation = validated.relation.clone();
    let source_session_id = candidate
        .source_session_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(session_id);
    let source_type = candidate
        .source_type
        .as_deref()
        .map(normalize_relation_name)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "conversation_session".to_string());
    let source_id = candidate
        .source_id
        .as_deref()
        .map(cleaned_text)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| source_session_id.to_string());

    let subject_aliases = normalize_aliases(&candidate.subject_aliases);
    let object_aliases = normalize_aliases(&candidate.object_aliases);
    let entity_hints = normalize_aliases(&candidate.entity_hints);

    let subject_entity_id = upsert_entity(
        conn,
        &subject,
        subject_aliases.clone(),
        &validated.subject_type,
        created_at_ms,
    )?;
    let object_entity_id = candidate
        .object_entity
        .as_deref()
        .map(cleaned_text)
        .filter(|value| !value.is_empty())
        .map(|object_entity| {
            upsert_entity(
                conn,
                &object_entity,
                object_aliases.clone(),
                validated.object_type.as_deref().unwrap_or("concept"),
                created_at_ms,
            )
        })
        .transpose()?
        .flatten();
    let object_name = object_entity_id.as_ref().map(|_| {
        candidate
            .object_entity
            .as_deref()
            .unwrap_or_default()
            .trim()
            .to_string()
    });
    let summary = cleaned_text(&candidate.summary);
    let fact_key = fact_key(
        source_session_id,
        &subject,
        &relation,
        &object_text,
        &summary,
    );
    let episode_id = upsert_episode(conn, session_id, created_at_ms, candidate)?;

    if let Some(existing) = conn
        .query_row(
            "SELECT id FROM knowledge_facts WHERE fact_key = ?1 LIMIT 1",
            params![fact_key],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    {
        return load_fact_record(conn, &existing)?
            .context("existing knowledge fact missing after dedupe lookup")
            .map(Some);
    }

    let fact_id = Uuid::new_v4().to_string();
    let provenance = merge_source_metadata(
        &candidate.source_metadata,
        &json!({
            "source": "conversation_import",
            "source_type": source_type,
            "source_id": source_id,
            "session_id": source_session_id,
            "source_role": candidate.source_role,
            "source_ordinal": candidate.source_ordinal,
        }),
    );
    conn.execute(
        "INSERT INTO knowledge_facts (
            id, fact_key, session_id, subject_entity_id, subject_name, subject_aliases_json,
            subject_aliases_text, relation, object_entity_id, object_name, object_aliases_json,
            object_aliases_text, object_text, summary, category, confidence, provenance_json,
            entity_hints_json, entity_hints_text, valid_from_ms, valid_to_ms, invalidated_at_ms,
            created_at_ms, updated_at_ms
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                  ?17, ?18, ?19, ?20, ?21, NULL, ?22, ?22)",
        params![
            &fact_id,
            fact_key,
            source_session_id,
            subject_entity_id.as_deref(),
            &subject,
            serde_json::to_string(&subject_aliases)?,
            subject_aliases.join("\n"),
            &relation,
            object_entity_id.as_deref(),
            object_name,
            serde_json::to_string(&object_aliases)?,
            object_aliases.join("\n"),
            &object_text,
            if summary.is_empty() {
                &object_text
            } else {
                &summary
            },
            candidate.category.trim(),
            candidate.confidence.trim(),
            serde_json::to_string(&provenance)?,
            serde_json::to_string(&entity_hints)?,
            entity_hints.join("\n"),
            candidate.valid_from_ms,
            candidate.valid_to_ms,
            created_at_ms,
        ],
    )?;
    insert_graph_projection(
        conn,
        &fact_id,
        episode_id.as_deref(),
        source_session_id,
        subject_entity_id.as_deref(),
        &subject,
        &relation,
        object_entity_id.as_deref(),
        object_name.as_deref(),
        &object_text,
        candidate,
        if summary.is_empty() {
            &object_text
        } else {
            &summary
        },
        created_at_ms,
        &validated,
    )?;
    load_fact_record(conn, &fact_id)?
        .context("stored knowledge fact missing after insert")
        .map(Some)
}

fn upsert_entity(
    conn: &Connection,
    canonical_name: &str,
    aliases: Vec<String>,
    entity_type: &str,
    created_at_ms: i64,
) -> Result<Option<String>> {
    let canonical_name = cleaned_text(canonical_name);
    if canonical_name.is_empty() {
        return Ok(None);
    }
    let normalized_name = normalize_entity_name(&canonical_name);
    if normalized_name.is_empty() {
        return Ok(None);
    }
    let aliases = normalize_aliases(&aliases);
    if let Some((existing_id, existing_type)) = conn
        .query_row(
            "SELECT id, entity_type FROM knowledge_entities WHERE normalized_name = ?1 LIMIT 1",
            params![normalized_name],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
    {
        let resolved_entity_type = merge_entity_type(&existing_type, entity_type);
        conn.execute(
            "UPDATE knowledge_entities
             SET canonical_name = ?2,
                 entity_type = ?3,
                 aliases_json = ?4,
                 aliases_text = ?5,
                 updated_at_ms = ?6
             WHERE id = ?1 OR normalized_name = ?7",
            params![
                &existing_id,
                &canonical_name,
                resolved_entity_type,
                serde_json::to_string(&aliases)?,
                aliases.join("\n"),
                created_at_ms,
                normalized_name,
            ],
        )?;
        store_aliases(conn, &existing_id, &aliases, created_at_ms)?;
        project_entity_self_links(
            conn,
            &existing_id,
            &canonical_name,
            &resolved_entity_type,
            created_at_ms,
        )?;
        return Ok(Some(existing_id));
    }

    let entity_id = Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO knowledge_entities (
            id, canonical_name, normalized_name, entity_type, aliases_json, aliases_text, metadata,
            created_at_ms, updated_at_ms
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
        params![
            &entity_id,
            &canonical_name,
            normalized_name,
            entity_type,
            serde_json::to_string(&aliases)?,
            aliases.join("\n"),
            serde_json::to_string(&json!({}))?,
            created_at_ms,
        ],
    )?;
    store_aliases(conn, &entity_id, &aliases, created_at_ms)?;
    project_entity_self_links(
        conn,
        &entity_id,
        &canonical_name,
        entity_type,
        created_at_ms,
    )?;
    Ok(Some(entity_id))
}

fn upsert_episode(
    conn: &Connection,
    session_id: &str,
    created_at_ms: i64,
    candidate: &KnowledgeFactCandidate,
) -> Result<Option<String>> {
    let source_session_id = candidate
        .source_session_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            let trimmed = session_id.trim();
            (!trimmed.is_empty()).then_some(trimmed)
        });
    let source_type = candidate
        .source_type
        .as_deref()
        .map(normalize_relation_name)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "conversation_session".to_string());
    let source_id = candidate
        .source_id
        .as_deref()
        .map(cleaned_text)
        .filter(|value| !value.is_empty())
        .or_else(|| source_session_id.map(ToOwned::to_owned));
    let Some(source_id) = source_id else {
        return Ok(None);
    };
    let summary = cleaned_text(&candidate.summary);
    if summary.is_empty() {
        return Ok(None);
    }
    let metadata = merge_source_metadata(
        &candidate.source_metadata,
        &json!({
            "source": "conversation_import",
            "source_type": source_type,
            "source_id": source_id,
            "session_id": source_session_id,
            "source_role": candidate.source_role,
            "source_ordinal": candidate.source_ordinal,
        }),
    );
    let episode_id = upsert_episode_record(
        conn,
        &source_type,
        &source_id,
        source_session_id,
        &summary,
        metadata,
        created_at_ms,
    )?;
    Ok(Some(episode_id))
}

fn upsert_episode_record(
    conn: &Connection,
    source_type: &str,
    source_id: &str,
    session_id: Option<&str>,
    summary: &str,
    metadata: Value,
    happened_at_ms: i64,
) -> Result<String> {
    let source_type = normalize_relation_name(source_type);
    let source_id = cleaned_text(source_id);
    let summary = cleaned_text(summary);
    if source_type.is_empty() || source_id.is_empty() || summary.is_empty() {
        anyhow::bail!("knowledge episode source_type/source_id/summary must not be empty");
    }
    let session_id = session_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let metadata_json = serde_json::to_string(&metadata)?;
    if let Some(existing_id) = conn
        .query_row(
            "SELECT id FROM knowledge_episodes WHERE source_type = ?1 AND source_id = ?2 LIMIT 1",
            params![&source_type, &source_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    {
        conn.execute(
            "UPDATE knowledge_episodes
             SET session_id = COALESCE(?2, session_id),
                 summary = ?3,
                 happened_at_ms = ?4,
                 metadata = ?5,
                 updated_at_ms = ?4
             WHERE id = ?1",
            params![
                &existing_id,
                session_id,
                summary,
                happened_at_ms,
                metadata_json
            ],
        )?;
        return Ok(existing_id);
    }

    let episode_id = Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO knowledge_episodes (
            id, session_id, source_type, source_id, summary, happened_at_ms, metadata,
            created_at_ms, updated_at_ms
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?6, ?6)",
        params![
            &episode_id,
            session_id,
            source_type,
            source_id,
            summary,
            happened_at_ms,
            metadata_json,
        ],
    )?;
    Ok(episode_id)
}

#[allow(clippy::too_many_arguments)]
fn insert_graph_projection(
    conn: &Connection,
    fact_id: &str,
    episode_id: Option<&str>,
    session_id: &str,
    subject_entity_id: Option<&str>,
    subject_name: &str,
    relation: &str,
    object_entity_id: Option<&str>,
    object_name: Option<&str>,
    object_text: &str,
    candidate: &KnowledgeFactCandidate,
    summary: &str,
    created_at_ms: i64,
    validated: &ValidatedKnowledgeCandidate,
) -> Result<()> {
    let edge_key = edge_key(session_id, subject_name, relation, object_text, summary);
    let edge_id = if let Some(existing_id) = conn
        .query_row(
            "SELECT id FROM knowledge_edges WHERE edge_key = ?1 LIMIT 1",
            params![&edge_key],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    {
        conn.execute(
            "UPDATE knowledge_edges
             SET fact_id = ?2,
                 episode_id = COALESCE(?3, episode_id),
                 session_id = ?4,
                 subject_entity_id = ?5,
                 subject_name = ?6,
                 relation = ?7,
                 object_entity_id = ?8,
                 object_name = ?9,
                 object_text = ?10,
                 summary = ?11,
                 category = ?12,
                 confidence = ?13,
                valid_from_ms = ?14,
                valid_to_ms = ?15,
                invalidated_at_ms = NULL,
                metadata = ?16,
                updated_at_ms = ?17
             WHERE id = ?1",
            params![
                &existing_id,
                fact_id,
                episode_id,
                session_id,
                subject_entity_id,
                subject_name,
                relation,
                object_entity_id,
                object_name,
                object_text,
                summary,
                candidate.category.trim(),
                candidate.confidence.trim(),
                candidate.valid_from_ms,
                candidate.valid_to_ms,
                serde_json::to_string(&json!({
                    "source": "conversation_import",
                    "source_role": candidate.source_role,
                    "source_ordinal": candidate.source_ordinal,
                    "subject_type": validated.subject_type,
                    "object_type": validated.object_type,
                    "cardinality": relation_cardinality_label(validated.cardinality),
                }))?,
                created_at_ms,
            ],
        )?;
        existing_id
    } else {
        let edge_id = Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO knowledge_edges (
                id, edge_key, fact_id, episode_id, session_id, subject_entity_id, subject_name,
                relation, object_entity_id, object_name, object_text, summary, category,
                confidence, valid_from_ms, valid_to_ms, invalidated_at_ms, metadata,
                created_at_ms, updated_at_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                      NULL, ?17, ?18, ?18)",
            params![
                &edge_id,
                &edge_key,
                fact_id,
                episode_id,
                session_id,
                subject_entity_id,
                subject_name,
                relation,
                object_entity_id,
                object_name,
                object_text,
                summary,
                candidate.category.trim(),
                candidate.confidence.trim(),
                candidate.valid_from_ms,
                candidate.valid_to_ms,
                serde_json::to_string(&json!({
                    "source": "conversation_import",
                    "source_role": candidate.source_role,
                    "source_ordinal": candidate.source_ordinal,
                    "subject_type": validated.subject_type,
                    "object_type": validated.object_type,
                    "cardinality": relation_cardinality_label(validated.cardinality),
                }))?,
                created_at_ms,
            ],
        )?;
        edge_id
    };
    apply_relation_cardinality(
        conn,
        &edge_id,
        relation,
        subject_entity_id,
        subject_name,
        object_entity_id,
        object_name,
        object_text,
        validated.cardinality,
        created_at_ms,
    )?;
    insert_edge_evidence(
        conn,
        &edge_id,
        episode_id,
        session_id,
        candidate,
        summary,
        created_at_ms,
    )?;
    project_relation_entity_links(
        conn,
        &edge_id,
        episode_id,
        subject_entity_id,
        relation,
        object_name,
        object_text,
        validated.object_type.as_deref(),
        created_at_ms,
    )?;
    Ok(())
}

fn insert_edge_evidence(
    conn: &Connection,
    edge_id: &str,
    episode_id: Option<&str>,
    session_id: &str,
    candidate: &KnowledgeFactCandidate,
    summary: &str,
    created_at_ms: i64,
) -> Result<()> {
    let Some(episode_id) = episode_id else {
        return Ok(());
    };
    let evidence_id = Uuid::new_v4().to_string();
    let snippet = candidate
        .evidence_snippet
        .as_deref()
        .map(cleaned_text)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| cleaned_text(summary));
    conn.execute(
        "INSERT OR IGNORE INTO knowledge_edge_evidence (
            id, edge_id, episode_id, session_id, source_role, source_ordinal, snippet, metadata,
            created_at_ms
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            evidence_id,
            edge_id,
            episode_id,
            session_id,
            candidate.source_role.trim(),
            candidate.source_ordinal as i64,
            snippet,
            serde_json::to_string(&merge_source_metadata(
                &candidate.source_metadata,
                &json!({
                    "source": "conversation_import",
                    "category": candidate.category,
                    "confidence": candidate.confidence,
                }),
            ))?,
            created_at_ms,
        ],
    )?;
    Ok(())
}

fn project_entity_self_links(
    conn: &Connection,
    entity_id: &str,
    canonical_name: &str,
    entity_type: &str,
    created_at_ms: i64,
) -> Result<usize> {
    let Some((link_type, target)) = infer_self_link(entity_type, canonical_name) else {
        return Ok(0);
    };
    Ok(usize::from(upsert_entity_link(
        conn,
        entity_id,
        link_type,
        &target,
        &json!({
            "source": "entity_projection",
            "entity_type": normalize_relation_name(entity_type),
        }),
        created_at_ms,
    )?))
}

fn project_relation_entity_links(
    conn: &Connection,
    edge_id: &str,
    episode_id: Option<&str>,
    subject_entity_id: Option<&str>,
    relation: &str,
    object_name: Option<&str>,
    object_text: &str,
    object_type: Option<&str>,
    created_at_ms: i64,
) -> Result<usize> {
    let Some(subject_entity_id) = subject_entity_id else {
        return Ok(0);
    };
    if normalize_relation_name(relation) != "located_in" {
        return Ok(0);
    }
    if object_type.map(normalize_relation_name).as_deref() != Some("file") {
        return Ok(0);
    }
    let target = cleaned_text(object_name.unwrap_or(object_text));
    if !looks_like_repo_file_target(&target) {
        return Ok(0);
    }
    Ok(usize::from(upsert_entity_link(
        conn,
        subject_entity_id,
        "file",
        &target,
        &json!({
            "source": "edge_projection",
            "edge_id": edge_id,
            "episode_id": episode_id,
            "relation": "located_in",
        }),
        created_at_ms,
    )?))
}

fn infer_self_link(entity_type: &str, canonical_name: &str) -> Option<(&'static str, String)> {
    let canonical_name = cleaned_text(canonical_name);
    if canonical_name.is_empty() {
        return None;
    }
    match normalize_relation_name(entity_type).as_str() {
        "file" if looks_like_repo_file_target(&canonical_name) => Some(("file", canonical_name)),
        "repo" => Some(("repo", canonical_name)),
        "symbol" if looks_like_symbol_target(&canonical_name) => Some(("symbol", canonical_name)),
        _ => None,
    }
}

fn looks_like_repo_file_target(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty() && !value.contains(' ') && (value.contains('/') || value.contains('\\'))
}

fn looks_like_symbol_target(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && !value.contains(' ')
        && (value.contains("::") || value.contains('#') || value.contains('.'))
}

fn upsert_entity_link(
    conn: &Connection,
    entity_id: &str,
    link_type: &str,
    target: &str,
    metadata: &Value,
    created_at_ms: i64,
) -> Result<bool> {
    let link_type = normalize_relation_name(link_type);
    let target = cleaned_text(target);
    if entity_id.trim().is_empty() || link_type.is_empty() || target.is_empty() {
        return Ok(false);
    }
    let existed = conn
        .query_row(
            "SELECT 1 FROM knowledge_entity_links WHERE entity_id = ?1 AND link_type = ?2 AND target = ?3 LIMIT 1",
            params![entity_id, &link_type, &target],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    conn.execute(
        "INSERT INTO knowledge_entity_links (
            id, entity_id, link_type, target, metadata, created_at_ms, updated_at_ms
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
        ON CONFLICT(entity_id, link_type, target) DO UPDATE
        SET metadata = excluded.metadata,
            updated_at_ms = excluded.updated_at_ms",
        params![
            Uuid::new_v4().to_string(),
            entity_id,
            link_type,
            target,
            serde_json::to_string(metadata)?,
            created_at_ms,
        ],
    )?;
    Ok(!existed)
}

fn delete_entity_links_for_edge(conn: &Connection, edge_id: &str) -> Result<usize> {
    Ok(conn.execute(
        "DELETE FROM knowledge_entity_links
         WHERE json_extract(metadata, '$.edge_id') = ?1",
        params![edge_id],
    )?)
}

fn delete_entity_links_for_episode(conn: &Connection, episode_id: &str) -> Result<usize> {
    Ok(conn.execute(
        "DELETE FROM knowledge_entity_links
         WHERE json_extract(metadata, '$.episode_id') = ?1",
        params![episode_id],
    )?)
}

fn rebuild_entity_self_links(conn: &Connection) -> Result<usize> {
    conn.execute(
        "DELETE FROM knowledge_entity_links
         WHERE json_extract(metadata, '$.source') = 'entity_projection'",
        [],
    )?;
    let mut stmt = conn.prepare(
        "SELECT id, canonical_name, entity_type, updated_at_ms
         FROM knowledge_entities
         ORDER BY updated_at_ms DESC, id ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })?;
    let mut projected = 0usize;
    for row in rows {
        let (entity_id, canonical_name, entity_type, updated_at_ms) = row?;
        projected += project_entity_self_links(
            conn,
            &entity_id,
            &canonical_name,
            &entity_type,
            updated_at_ms,
        )?;
    }
    Ok(projected)
}

fn rebuild_relation_entity_links(conn: &Connection) -> Result<usize> {
    conn.execute(
        "DELETE FROM knowledge_entity_links
         WHERE json_extract(metadata, '$.source') = 'edge_projection'",
        [],
    )?;
    let mut stmt = conn.prepare(
        "SELECT id, episode_id, subject_entity_id, relation, object_name, object_text, metadata,
                updated_at_ms
         FROM knowledge_edges
         WHERE invalidated_at_ms IS NULL
         ORDER BY updated_at_ms DESC, id ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, i64>(7)?,
        ))
    })?;
    let mut projected = 0usize;
    for row in rows {
        let (
            edge_id,
            episode_id,
            subject_entity_id,
            relation,
            object_name,
            object_text,
            metadata_json,
            updated_at_ms,
        ) = row?;
        let object_type = serde_json::from_str::<Value>(&metadata_json)
            .ok()
            .and_then(|value| {
                value
                    .get("object_type")
                    .and_then(|item| item.as_str())
                    .map(ToOwned::to_owned)
            });
        let Some(subject_entity_id) = subject_entity_id else {
            continue;
        };
        projected += project_relation_entity_links(
            conn,
            &edge_id,
            episode_id.as_deref(),
            Some(&subject_entity_id),
            &relation,
            object_name.as_deref(),
            &object_text,
            object_type.as_deref(),
            updated_at_ms,
        )?;
    }
    Ok(projected)
}

fn merge_source_metadata(primary: &Value, overlay: &Value) -> Value {
    let mut merged = match primary.clone() {
        Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    if let Value::Object(overlay_map) = overlay {
        for (key, value) in overlay_map {
            merged.insert(key.clone(), value.clone());
        }
    }
    Value::Object(merged)
}

#[allow(clippy::too_many_arguments)]
fn apply_relation_cardinality(
    conn: &Connection,
    edge_id: &str,
    relation: &str,
    subject_entity_id: Option<&str>,
    subject_name: &str,
    object_entity_id: Option<&str>,
    object_name: Option<&str>,
    object_text: &str,
    cardinality: RelationCardinality,
    created_at_ms: i64,
) -> Result<()> {
    match cardinality {
        RelationCardinality::ManyToMany => Ok(()),
        RelationCardinality::ManyToOne => invalidate_conflicting_edges(
            conn,
            edge_id,
            relation,
            subject_entity_id,
            Some(subject_name),
            None,
            None,
            created_at_ms,
            "subject_unique",
        ),
        RelationCardinality::OneToMany => invalidate_conflicting_edges(
            conn,
            edge_id,
            relation,
            None,
            None,
            object_entity_id,
            object_name.or(Some(object_text)),
            created_at_ms,
            "object_unique",
        ),
        RelationCardinality::OneToOne => {
            invalidate_conflicting_edges(
                conn,
                edge_id,
                relation,
                subject_entity_id,
                Some(subject_name),
                None,
                None,
                created_at_ms,
                "subject_unique",
            )?;
            invalidate_conflicting_edges(
                conn,
                edge_id,
                relation,
                None,
                None,
                object_entity_id,
                object_name.or(Some(object_text)),
                created_at_ms,
                "object_unique",
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn invalidate_conflicting_edges(
    conn: &Connection,
    edge_id: &str,
    relation: &str,
    subject_entity_id: Option<&str>,
    subject_name: Option<&str>,
    object_entity_id: Option<&str>,
    object_name_or_text: Option<&str>,
    created_at_ms: i64,
    reason: &str,
) -> Result<()> {
    let mut stmt = conn.prepare(
        "SELECT id, fact_id, subject_entity_id, subject_name, object_entity_id, object_name, object_text
         FROM knowledge_edges
         WHERE relation = ?1
           AND id != ?2
           AND invalidated_at_ms IS NULL",
    )?;
    let rows = stmt.query_map(params![relation, edge_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, String>(6)?,
        ))
    })?;
    for row in rows {
        let (
            conflicting_edge_id,
            conflicting_fact_id,
            conflicting_subject_entity_id,
            conflicting_subject_name,
            conflicting_object_entity_id,
            conflicting_object_name,
            conflicting_object_text,
        ) = row?;
        let subject_matches = match (subject_entity_id, subject_name) {
            (Some(entity_id), _) => conflicting_subject_entity_id.as_deref() == Some(entity_id),
            (None, Some(name)) => conflicting_subject_name.eq_ignore_ascii_case(name),
            (None, None) => true,
        };
        let object_matches = match (object_entity_id, object_name_or_text) {
            (Some(entity_id), _) => conflicting_object_entity_id.as_deref() == Some(entity_id),
            (None, Some(name_or_text)) => conflicting_object_name
                .as_deref()
                .map(|value| value.eq_ignore_ascii_case(name_or_text))
                .unwrap_or_else(|| conflicting_object_text.eq_ignore_ascii_case(name_or_text)),
            (None, None) => true,
        };
        if !subject_matches || !object_matches {
            continue;
        }
        conn.execute(
            "UPDATE knowledge_edges
             SET invalidated_at_ms = ?2,
                 updated_at_ms = ?2
             WHERE id = ?1",
            params![&conflicting_edge_id, created_at_ms],
        )?;
        if let Some(fact_id) = conflicting_fact_id.as_deref() {
            conn.execute(
                "UPDATE knowledge_facts
                 SET invalidated_at_ms = ?2,
                     updated_at_ms = ?2
                 WHERE id = ?1",
                params![fact_id, created_at_ms],
            )?;
        }
        let invalidation_id = Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO knowledge_edge_invalidations (
                id, edge_id, invalidated_at_ms, reason, replacement_edge_id, metadata
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                invalidation_id,
                &conflicting_edge_id,
                created_at_ms,
                reason,
                edge_id,
                serde_json::to_string(&json!({
                    "source": "graph_ontology",
                    "relation": relation,
                }))?,
            ],
        )?;
    }
    Ok(())
}

fn relation_cardinality_label(cardinality: RelationCardinality) -> &'static str {
    match cardinality {
        RelationCardinality::ManyToMany => "many_to_many",
        RelationCardinality::OneToMany => "one_to_many",
        RelationCardinality::ManyToOne => "many_to_one",
        RelationCardinality::OneToOne => "one_to_one",
    }
}

fn merge_entity_type(existing: &str, next: &str) -> String {
    let existing = normalize_entity_name(existing);
    let next = normalize_entity_name(next);
    if next.is_empty() {
        return existing;
    }
    if existing.is_empty() {
        return next;
    }
    if entity_type_rank(&next) >= entity_type_rank(&existing) {
        next
    } else {
        existing
    }
}

fn entity_type_rank(value: &str) -> usize {
    match value {
        "conversation_subject" | "conversation_object" | "concept" => 0,
        "repo" => 1,
        "decision" | "preference" | "constraint" | "workflow" | "tool" => 2,
        "file" => 3,
        "symbol" => 4,
        _ => 1,
    }
}

fn store_aliases(
    conn: &Connection,
    entity_id: &str,
    aliases: &[String],
    created_at_ms: i64,
) -> Result<()> {
    for alias in aliases {
        let normalized_alias = normalize_entity_name(alias);
        if normalized_alias.is_empty() {
            continue;
        }
        conn.execute(
            "INSERT OR IGNORE INTO knowledge_aliases (
                normalized_alias, alias, entity_id, created_at_ms
            ) VALUES (?1, ?2, ?3, ?4)",
            params![normalized_alias, alias, entity_id, created_at_ms],
        )?;
    }
    Ok(())
}

fn load_entities(
    conn: &Connection,
    normalized_query: &str,
    entity_type: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<Vec<KnowledgeEntityRecord>> {
    let like = format!("%{normalized_query}%");
    let mut stmt = conn.prepare(
        "SELECT DISTINCT ke.id, ke.canonical_name, ke.entity_type, ke.aliases_json, ke.updated_at_ms, ke.metadata
         FROM knowledge_entities ke
         LEFT JOIN knowledge_aliases ka ON ka.entity_id = ke.id
         WHERE (?3 IS NULL OR ke.entity_type = ?3)
           AND (
                ke.normalized_name = ?1
             OR ke.normalized_name LIKE ?2
             OR ka.normalized_alias = ?1
             OR ka.normalized_alias LIKE ?2
           )
         ORDER BY ke.updated_at_ms DESC, ke.canonical_name ASC
         LIMIT ?4 OFFSET ?5",
    )?;
    let rows = stmt.query_map(
        params![
            normalized_query,
            like,
            entity_type,
            limit as i64,
            offset as i64
        ],
        |row| {
            let aliases_json: String = row.get(3)?;
            let metadata_json: String = row.get(5)?;
            Ok(KnowledgeEntityRecord {
                entity_id: row.get(0)?,
                canonical_name: row.get(1)?,
                entity_type: row.get(2)?,
                aliases: serde_json::from_str(&aliases_json).unwrap_or_default(),
                updated_at_ms: row.get(4)?,
                metadata: serde_json::from_str(&metadata_json).unwrap_or_else(|_| json!({})),
            })
        },
    )?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

fn count_entities(
    conn: &Connection,
    normalized_query: &str,
    entity_type: Option<&str>,
) -> Result<usize> {
    let like = format!("%{normalized_query}%");
    let total = conn.query_row(
        "SELECT COUNT(DISTINCT ke.id)
         FROM knowledge_entities ke
         LEFT JOIN knowledge_aliases ka ON ka.entity_id = ke.id
         WHERE (?3 IS NULL OR ke.entity_type = ?3)
           AND (
                ke.normalized_name = ?1
             OR ke.normalized_name LIKE ?2
             OR ka.normalized_alias = ?1
             OR ka.normalized_alias LIKE ?2
           )",
        params![normalized_query, like, entity_type],
        |row| row.get::<_, i64>(0),
    )?;
    Ok(total.max(0) as usize)
}

fn count_entity_links(
    conn: &Connection,
    entity_id: &str,
    link_type: Option<&str>,
) -> Result<usize> {
    let total = if let Some(link_type) = link_type {
        conn.query_row(
            "SELECT COUNT(*) FROM knowledge_entity_links WHERE entity_id = ?1 AND link_type = ?2",
            params![entity_id, link_type],
            |row| row.get::<_, i64>(0),
        )?
    } else {
        conn.query_row(
            "SELECT COUNT(*) FROM knowledge_entity_links WHERE entity_id = ?1",
            params![entity_id],
            |row| row.get::<_, i64>(0),
        )?
    };
    Ok(total.max(0) as usize)
}

fn load_entity_links(
    conn: &Connection,
    entity_id: &str,
    link_type: Option<&str>,
    limit: usize,
) -> Result<Vec<KnowledgeEntityLinkRecord>> {
    let limit = limit.max(1);
    if let Some(link_type) = link_type {
        let mut stmt = conn.prepare(
            "SELECT
                l.id,
                l.entity_id,
                e.canonical_name,
                e.entity_type,
                l.link_type,
                l.target,
                l.metadata,
                l.created_at_ms,
                l.updated_at_ms
             FROM knowledge_entity_links l
             JOIN knowledge_entities e ON e.id = l.entity_id
             WHERE l.entity_id = ?1 AND l.link_type = ?2
             ORDER BY l.updated_at_ms DESC, l.id ASC
             LIMIT ?3",
        )?;
        let rows = stmt.query_map(
            params![entity_id, link_type, limit as i64],
            map_entity_link_row,
        )?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    } else {
        let mut stmt = conn.prepare(
            "SELECT
                l.id,
                l.entity_id,
                e.canonical_name,
                e.entity_type,
                l.link_type,
                l.target,
                l.metadata,
                l.created_at_ms,
                l.updated_at_ms
             FROM knowledge_entity_links l
             JOIN knowledge_entities e ON e.id = l.entity_id
             WHERE l.entity_id = ?1
             ORDER BY l.updated_at_ms DESC, l.id ASC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![entity_id, limit as i64], map_entity_link_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }
}

fn map_entity_link_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<KnowledgeEntityLinkRecord> {
    let metadata_json: String = row.get(6)?;
    Ok(KnowledgeEntityLinkRecord {
        link_id: row.get(0)?,
        entity_id: row.get(1)?,
        entity_name: row.get(2)?,
        entity_type: row.get(3)?,
        link_type: row.get(4)?,
        target: row.get(5)?,
        metadata: serde_json::from_str(&metadata_json).unwrap_or_else(|_| json!({})),
        created_at_ms: row.get(7)?,
        updated_at_ms: row.get(8)?,
    })
}

fn count_edges(conn: &Connection, normalized_query: &str, relation: Option<&str>) -> Result<usize> {
    let like = format!("%{normalized_query}%");
    let total = conn.query_row(
        "SELECT COUNT(*)
         FROM knowledge_edges
         WHERE (?1 IS NULL OR relation = ?1)
           AND (
                LOWER(subject_name) = ?2
             OR LOWER(subject_name) LIKE ?3
             OR LOWER(COALESCE(object_name, '')) = ?2
             OR LOWER(COALESCE(object_name, '')) LIKE ?3
             OR LOWER(object_text) LIKE ?3
             OR LOWER(summary) LIKE ?3
           )",
        params![relation, normalized_query, like],
        |row| row.get::<_, i64>(0),
    )?;
    Ok(total.max(0) as usize)
}

fn load_edges_for_search(
    conn: &Connection,
    normalized_query: &str,
    relation: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<Vec<KnowledgeGraphEdgeRecord>> {
    let like = format!("%{normalized_query}%");
    let mut stmt = conn.prepare(
        "SELECT id, fact_id, episode_id, session_id, subject_entity_id, subject_name, relation,
                object_entity_id, object_name, object_text, category, confidence, summary,
                valid_from_ms, valid_to_ms, invalidated_at_ms, created_at_ms, updated_at_ms
         FROM knowledge_edges
         WHERE (?1 IS NULL OR relation = ?1)
           AND (
                LOWER(subject_name) = ?2
             OR LOWER(subject_name) LIKE ?3
             OR LOWER(COALESCE(object_name, '')) = ?2
             OR LOWER(COALESCE(object_name, '')) LIKE ?3
             OR LOWER(object_text) LIKE ?3
             OR LOWER(summary) LIKE ?3
           )
         ORDER BY updated_at_ms DESC, id ASC
         LIMIT ?4 OFFSET ?5",
    )?;
    let rows = stmt.query_map(
        params![
            relation,
            normalized_query,
            like,
            limit as i64,
            offset as i64
        ],
        map_edge_row,
    )?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

fn count_episodes(
    conn: &Connection,
    normalized_query: &str,
    source_type: Option<&str>,
) -> Result<usize> {
    let like = format!("%{normalized_query}%");
    let total = conn.query_row(
        "SELECT COUNT(*)
         FROM knowledge_episodes
         WHERE (?1 IS NULL OR source_type = ?1)
           AND (
                LOWER(source_id) LIKE ?2
             OR LOWER(COALESCE(session_id, '')) LIKE ?2
             OR LOWER(summary) LIKE ?2
             OR LOWER(metadata) LIKE ?2
           )",
        params![source_type, like],
        |row| row.get::<_, i64>(0),
    )?;
    Ok(total.max(0) as usize)
}

fn load_episodes(
    conn: &Connection,
    normalized_query: &str,
    source_type: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<Vec<KnowledgeEpisodeRecord>> {
    let like = format!("%{normalized_query}%");
    let mut stmt = conn.prepare(
        "SELECT id, session_id, source_type, source_id, summary, happened_at_ms, metadata,
                created_at_ms, updated_at_ms
         FROM knowledge_episodes
         WHERE (?1 IS NULL OR source_type = ?1)
           AND (
                LOWER(source_id) LIKE ?2
             OR LOWER(COALESCE(session_id, '')) LIKE ?2
             OR LOWER(summary) LIKE ?2
             OR LOWER(metadata) LIKE ?2
           )
         ORDER BY happened_at_ms DESC, id ASC
         LIMIT ?3 OFFSET ?4",
    )?;
    let rows = stmt.query_map(
        params![source_type, like, limit as i64, offset as i64],
        map_episode_row,
    )?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

fn load_episode_record(
    conn: &Connection,
    episode_id: &str,
) -> Result<Option<KnowledgeEpisodeRecord>> {
    conn.query_row(
        "SELECT id, session_id, source_type, source_id, summary, happened_at_ms, metadata,
                created_at_ms, updated_at_ms
         FROM knowledge_episodes
         WHERE id = ?1
         LIMIT 1",
        params![episode_id],
        map_episode_row,
    )
    .optional()
    .context("load knowledge episode")
}

fn load_episode_record_for_source(
    conn: &Connection,
    source_type: &str,
    source_id: &str,
) -> Result<Option<KnowledgeEpisodeRecord>> {
    conn.query_row(
        "SELECT id, session_id, source_type, source_id, summary, happened_at_ms, metadata,
                created_at_ms, updated_at_ms
         FROM knowledge_episodes
         WHERE source_type = ?1 AND source_id = ?2
         LIMIT 1",
        params![source_type, source_id],
        map_episode_row,
    )
    .optional()
    .context("load knowledge episode by source")
}

fn count_edges_for_episode(conn: &Connection, episode_id: &str) -> Result<usize> {
    let total = conn.query_row(
        "SELECT COUNT(*) FROM knowledge_edges WHERE episode_id = ?1",
        params![episode_id],
        |row| row.get::<_, i64>(0),
    )?;
    Ok(total.max(0) as usize)
}

fn load_edges_for_episode(
    conn: &Connection,
    episode_id: &str,
    limit: usize,
) -> Result<Vec<KnowledgeGraphEdgeRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, fact_id, episode_id, session_id, subject_entity_id, subject_name, relation,
                object_entity_id, object_name, object_text, category, confidence, summary,
                valid_from_ms, valid_to_ms, invalidated_at_ms, created_at_ms, updated_at_ms
         FROM knowledge_edges
         WHERE episode_id = ?1
         ORDER BY updated_at_ms DESC, id ASC
         LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![episode_id, limit as i64], map_edge_row)?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

fn load_evidence_for_episode(
    conn: &Connection,
    episode_id: &str,
    edge_ids: &HashSet<String>,
) -> Result<Vec<KnowledgeEdgeEvidenceRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, edge_id, episode_id, session_id, source_role, source_ordinal, snippet, metadata,
                created_at_ms
         FROM knowledge_edge_evidence
         WHERE episode_id = ?1
         ORDER BY COALESCE(source_ordinal, 0) ASC, created_at_ms ASC, id ASC",
    )?;
    let rows = stmt.query_map(params![episode_id], map_edge_evidence_row)?;
    let mut evidence = Vec::new();
    for row in rows {
        let record = row?;
        if !edge_ids.is_empty() && !edge_ids.contains(&record.edge_id) {
            continue;
        }
        evidence.push(record);
    }
    Ok(evidence)
}

fn count_neighborhood_edges(
    conn: &Connection,
    normalized_entity: &str,
    relation: Option<&str>,
    entity_ids: &HashSet<String>,
) -> Result<usize> {
    Ok(load_neighborhood_edges(conn, normalized_entity, relation, entity_ids, usize::MAX)?.len())
}

fn load_neighborhood_edges(
    conn: &Connection,
    normalized_entity: &str,
    relation: Option<&str>,
    entity_ids: &HashSet<String>,
    limit: usize,
) -> Result<Vec<KnowledgeGraphEdgeRecord>> {
    let term = normalized_entity;
    let mut stmt = conn.prepare(
        "SELECT id, fact_id, episode_id, session_id, subject_entity_id, subject_name, relation,
                object_entity_id, object_name, object_text, category, confidence, summary,
                valid_from_ms, valid_to_ms, invalidated_at_ms, created_at_ms, updated_at_ms
         FROM knowledge_edges
         WHERE (?1 IS NULL OR relation = ?1)
         ORDER BY updated_at_ms DESC, id ASC",
    )?;
    let rows = stmt.query_map(params![relation], map_edge_row)?;
    let mut edges = Vec::new();
    for row in rows {
        let edge = row?;
        let entity_match = if entity_ids.is_empty() {
            let subject = edge.subject.to_ascii_lowercase();
            let object_entity = edge
                .object_entity
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase();
            let object_text = edge.object_text.to_ascii_lowercase();
            let summary = edge.summary.to_ascii_lowercase();
            subject == term
                || subject.contains(term)
                || object_entity == term
                || object_entity.contains(term)
                || object_text.contains(term)
                || summary.contains(term)
        } else {
            edge.subject_entity_id
                .as_ref()
                .map(|id| entity_ids.contains(id))
                .unwrap_or(false)
                || edge
                    .object_entity_id
                    .as_ref()
                    .map(|id| entity_ids.contains(id))
                    .unwrap_or(false)
        };
        if !entity_match {
            continue;
        }
        edges.push(edge);
        if edges.len() >= limit {
            break;
        }
    }
    Ok(edges)
}

fn map_episode_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<KnowledgeEpisodeRecord> {
    let metadata_json: String = row.get(6)?;
    Ok(KnowledgeEpisodeRecord {
        episode_id: row.get(0)?,
        session_id: row.get(1)?,
        source_type: row.get(2)?,
        source_id: row.get(3)?,
        summary: row.get(4)?,
        happened_at_ms: row.get(5)?,
        metadata: serde_json::from_str(&metadata_json).unwrap_or_else(|_| json!({})),
        created_at_ms: row.get(7)?,
        updated_at_ms: row.get(8)?,
    })
}

fn map_edge_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<KnowledgeGraphEdgeRecord> {
    Ok(KnowledgeGraphEdgeRecord {
        edge_id: row.get(0)?,
        fact_id: row.get(1)?,
        episode_id: row.get(2)?,
        session_id: row.get(3)?,
        subject_entity_id: row.get(4)?,
        subject: row.get(5)?,
        relation: row.get(6)?,
        object_entity_id: row.get(7)?,
        object_entity: row.get(8)?,
        object_text: row.get(9)?,
        category: row.get(10)?,
        confidence: row.get(11)?,
        summary: row.get(12)?,
        valid_from_ms: row.get(13)?,
        valid_to_ms: row.get(14)?,
        invalidated_at_ms: row.get(15)?,
        created_at_ms: row.get(16)?,
        updated_at_ms: row.get(17)?,
    })
}

fn map_edge_evidence_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<KnowledgeEdgeEvidenceRecord> {
    let metadata_json: String = row.get(7)?;
    Ok(KnowledgeEdgeEvidenceRecord {
        evidence_id: row.get(0)?,
        edge_id: row.get(1)?,
        episode_id: row.get(2)?,
        session_id: row.get(3)?,
        source_role: row.get(4)?,
        source_ordinal: row
            .get::<_, Option<i64>>(5)?
            .map(|value| value.max(0) as usize),
        snippet: row.get(6)?,
        metadata: serde_json::from_str(&metadata_json).unwrap_or_else(|_| json!({})),
        created_at_ms: row.get(8)?,
    })
}

fn load_facts_for_query(
    conn: &Connection,
    normalized_query: &str,
    relation: Option<&str>,
) -> Result<Vec<KnowledgeFactRecord>> {
    let like = format!("%{normalized_query}%");
    let mut stmt = conn.prepare(
        "SELECT id
         FROM knowledge_facts
         WHERE (?1 IS NULL OR relation = ?1)
           AND (
                LOWER(subject_name) = ?2
             OR LOWER(subject_name) LIKE ?3
             OR LOWER(COALESCE(object_name, '')) = ?2
             OR LOWER(COALESCE(object_name, '')) LIKE ?3
             OR LOWER(object_text) LIKE ?3
             OR LOWER(summary) LIKE ?3
             OR LOWER(subject_aliases_text) LIKE ?3
             OR LOWER(object_aliases_text) LIKE ?3
             OR LOWER(entity_hints_text) LIKE ?3
           )",
    )?;
    let ids = stmt
        .query_map(params![relation, normalized_query, like], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    load_facts_by_ids(conn, &ids)
}

fn load_facts_for_timeline(
    conn: &Connection,
    normalized_entity: &str,
    relation: Option<&str>,
    entity_ids: &HashSet<String>,
) -> Result<Vec<KnowledgeFactRecord>> {
    let like = format!("%{normalized_entity}%");
    let mut ids = Vec::new();
    if entity_ids.is_empty() {
        let mut stmt = conn.prepare(
            "SELECT id
             FROM knowledge_facts
             WHERE (?1 IS NULL OR relation = ?1)
               AND (
                    LOWER(subject_name) = ?2
                 OR LOWER(subject_name) LIKE ?3
                 OR LOWER(COALESCE(object_name, '')) = ?2
                 OR LOWER(COALESCE(object_name, '')) LIKE ?3
                 OR LOWER(object_text) LIKE ?3
                 OR LOWER(summary) LIKE ?3
                 OR LOWER(entity_hints_text) LIKE ?3
               )",
        )?;
        ids = stmt
            .query_map(params![relation, normalized_entity, like], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
    } else {
        let mut stmt = conn.prepare(
            "SELECT id, subject_entity_id, object_entity_id
             FROM knowledge_facts
             WHERE (?1 IS NULL OR relation = ?1)",
        )?;
        let rows = stmt.query_map(params![relation], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?;
        for row in rows {
            let (fact_id, subject_entity_id, object_entity_id) = row?;
            let matched = subject_entity_id
                .as_ref()
                .map(|id| entity_ids.contains(id))
                .unwrap_or(false)
                || object_entity_id
                    .as_ref()
                    .map(|id| entity_ids.contains(id))
                    .unwrap_or(false);
            if matched {
                ids.push(fact_id);
            }
        }
    }
    load_facts_by_ids(conn, &ids)
}

fn load_facts_by_session(conn: &Connection, session_id: &str) -> Result<Vec<KnowledgeFactRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id FROM knowledge_facts
         WHERE session_id = ?1
         ORDER BY updated_at_ms DESC, id ASC",
    )?;
    let ids = stmt
        .query_map(params![session_id], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    load_facts_by_ids(conn, &ids)
}

fn load_facts_by_ids(conn: &Connection, ids: &[String]) -> Result<Vec<KnowledgeFactRecord>> {
    let mut facts = Vec::with_capacity(ids.len());
    for id in ids {
        if let Some(fact) = load_fact_record(conn, id)? {
            facts.push(fact);
        }
    }
    Ok(facts)
}

fn load_fact_record(conn: &Connection, fact_id: &str) -> Result<Option<KnowledgeFactRecord>> {
    conn.query_row(
        "SELECT id, session_id, subject_entity_id, subject_name, subject_aliases_json, relation, object_text,
                object_name, object_aliases_json, category, confidence, summary, entity_hints_json,
                valid_from_ms, valid_to_ms, invalidated_at_ms, created_at_ms, updated_at_ms,
                provenance_json
         FROM knowledge_facts
         WHERE id = ?1
         LIMIT 1",
        params![fact_id],
        |row| {
            let subject_aliases_json: String = row.get(4)?;
            let object_aliases_json: String = row.get(8)?;
            let entity_hints_json: String = row.get(12)?;
            let provenance_json: String = row.get(18)?;
            let provenance: Value =
                serde_json::from_str(&provenance_json).unwrap_or_else(|_| json!({}));
            Ok(KnowledgeFactRecord {
                fact_id: row.get(0)?,
                session_id: row.get(1)?,
                subject_entity_id: row.get(2)?,
                subject: row.get(3)?,
                subject_aliases: serde_json::from_str(&subject_aliases_json).unwrap_or_default(),
                relation: row.get(5)?,
                object_text: row.get(6)?,
                object_entity: row.get(7)?,
                object_aliases: serde_json::from_str(&object_aliases_json).unwrap_or_default(),
                category: row.get(9)?,
                confidence: row.get(10)?,
                summary: row.get(11)?,
                entity_hints: serde_json::from_str(&entity_hints_json).unwrap_or_default(),
                valid_from_ms: row.get(13)?,
                valid_to_ms: row.get(14)?,
                invalidated_at_ms: row.get(15)?,
                created_at_ms: row.get(16)?,
                updated_at_ms: row.get(17)?,
                source_role: provenance
                    .get("source_role")
                    .and_then(|value| value.as_str())
                    .map(ToOwned::to_owned),
                source_ordinal: provenance
                    .get("source_ordinal")
                    .and_then(|value| value.as_u64())
                    .map(|value| value as usize),
                episode_id: None,
            })
        },
    )
    .optional()
    .context("load knowledge fact")
}

fn gc_orphaned_entities(conn: &Connection) -> Result<()> {
    let mut subject_counts = HashMap::<String, usize>::new();
    let mut object_counts = HashMap::<String, usize>::new();
    let mut stmt = conn.prepare(
        "SELECT subject_entity_id, object_entity_id FROM knowledge_facts WHERE invalidated_at_ms IS NULL",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0)?,
            row.get::<_, Option<String>>(1)?,
        ))
    })?;
    for row in rows {
        let (subject_entity_id, object_entity_id) = row?;
        if let Some(subject_entity_id) = subject_entity_id {
            *subject_counts.entry(subject_entity_id).or_default() += 1;
        }
        if let Some(object_entity_id) = object_entity_id {
            *object_counts.entry(object_entity_id).or_default() += 1;
        }
    }
    let mut edge_stmt = conn.prepare(
        "SELECT subject_entity_id, object_entity_id FROM knowledge_edges WHERE invalidated_at_ms IS NULL",
    )?;
    let edge_rows = edge_stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0)?,
            row.get::<_, Option<String>>(1)?,
        ))
    })?;
    for row in edge_rows {
        let (subject_entity_id, object_entity_id) = row?;
        if let Some(subject_entity_id) = subject_entity_id {
            *subject_counts.entry(subject_entity_id).or_default() += 1;
        }
        if let Some(object_entity_id) = object_entity_id {
            *object_counts.entry(object_entity_id).or_default() += 1;
        }
    }

    let retained = subject_counts
        .into_keys()
        .chain(object_counts.into_keys())
        .collect::<HashSet<_>>();
    let mut stmt = conn.prepare("SELECT id FROM knowledge_entities")?;
    let entity_ids = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for entity_id in entity_ids {
        if retained.contains(&entity_id) {
            continue;
        }
        conn.execute(
            "DELETE FROM knowledge_entity_links WHERE entity_id = ?1",
            params![&entity_id],
        )?;
        conn.execute(
            "DELETE FROM knowledge_aliases WHERE entity_id = ?1",
            params![&entity_id],
        )?;
        conn.execute(
            "DELETE FROM knowledge_entities WHERE id = ?1",
            params![&entity_id],
        )?;
    }
    Ok(())
}

fn fact_key(
    session_id: &str,
    subject: &str,
    relation: &str,
    object_text: &str,
    summary: &str,
) -> String {
    let digest = sha2::Sha256::digest(
        format!(
            "{}\n{}\n{}\n{}\n{}",
            session_id,
            normalize_entity_name(subject),
            normalize_relation_name(relation),
            object_text.to_ascii_lowercase(),
            summary.to_ascii_lowercase()
        )
        .as_bytes(),
    );
    format!("{digest:x}")
}

fn edge_key(
    session_id: &str,
    subject: &str,
    relation: &str,
    object_text: &str,
    summary: &str,
) -> String {
    fact_key(session_id, subject, relation, object_text, summary)
}

fn normalize_aliases(values: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut aliases = Vec::new();
    for value in values {
        let cleaned = cleaned_text(value);
        let normalized = normalize_entity_name(&cleaned);
        if cleaned.is_empty() || normalized.is_empty() || !seen.insert(normalized) {
            continue;
        }
        aliases.push(cleaned);
    }
    aliases
}

fn cleaned_text(value: &str) -> String {
    value
        .split_whitespace()
        .filter(|item| !item.trim().is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .trim_matches(|ch: char| matches!(ch, '"' | '\'' | '`'))
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn candidate(
        subject: &str,
        relation: &str,
        object_text: &str,
        summary: &str,
    ) -> KnowledgeFactCandidate {
        KnowledgeFactCandidate {
            subject: subject.to_string(),
            relation: relation.to_string(),
            object_text: object_text.to_string(),
            category: "repo_fact".to_string(),
            confidence: "high".to_string(),
            source_role: "assistant".to_string(),
            summary: summary.to_string(),
            ..KnowledgeFactCandidate::default()
        }
    }

    #[test]
    fn stores_and_queries_knowledge_candidates() -> Result<()> {
        let state = TempDir::new()?;
        let store = KnowledgeStore::new(state.path());
        let facts = store.store_candidates(
            "session-1",
            1_000,
            &[KnowledgeFactCandidate {
                subject_type_hint: Some("symbol".to_string()),
                subject_aliases: vec!["wake-up".to_string()],
                object_entity: Some("src/api/v1/wakeup.rs".to_string()),
                object_type_hint: Some("file".to_string()),
                source_role: "developer".to_string(),
                entity_hints: vec![
                    "wake-up endpoint".to_string(),
                    "src/api/v1/wakeup.rs".to_string(),
                ],
                valid_from_ms: Some(1_000),
                ..candidate(
                    "wake-up endpoint",
                    "located_in",
                    "src/api/v1/wakeup.rs",
                    "The wake-up endpoint lives in src/api/v1/wakeup.rs.",
                )
            }],
        )?;

        assert_eq!(facts.len(), 1);
        let query = store.query_facts("wakeup.rs", None, 10, 0)?;
        assert_eq!(query.total, 1);

        let timeline = store.timeline_for_entity("wake-up endpoint", None, 10)?;
        assert_eq!(timeline.total, 1);
        assert_eq!(timeline.events[0].relation, "located_in");

        let nodes = store.search_nodes("wake-up", None, 10, 0)?;
        assert_eq!(nodes.total, 1);
        assert_eq!(nodes.nodes[0].canonical_name, "wake-up endpoint");

        let neighborhood = store.neighborhood_for_entity("wake-up endpoint", None, 10)?;
        assert_eq!(neighborhood.total, 1);
        assert_eq!(neighborhood.edges[0].relation, "located_in");
        let episode_id = neighborhood.edges[0]
            .episode_id
            .clone()
            .expect("graph projection should store episode ids");

        let edge_search = store.search_edges("wakeup.rs", None, 10, 0)?;
        assert_eq!(edge_search.total, 1);
        assert_eq!(edge_search.edges[0].relation, "located_in");

        let episodes = store.search_episodes("wake-up", None, 10, 0)?;
        assert_eq!(episodes.total, 1);
        assert_eq!(episodes.episodes[0].episode_id, episode_id);

        let episode = store
            .episode_details(&episode_id, 10)?
            .expect("stored episode should be retrievable");
        assert_eq!(episode.total_edges, 1);
        assert_eq!(episode.edges.len(), 1);
        assert_eq!(episode.evidence.len(), 1);
        assert_eq!(
            episode.evidence[0].source_role.as_deref(),
            Some("developer")
        );

        let conn = Connection::open(store.path())?;
        let edge_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM knowledge_edges", [], |row| row.get(0))?;
        let episode_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM knowledge_episodes", [], |row| {
                row.get(0)
            })?;
        let evidence_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM knowledge_edge_evidence", [], |row| {
                row.get(0)
            })?;
        assert_eq!(edge_count, 1);
        assert_eq!(episode_count, 1);
        assert_eq!(evidence_count, 1);
        Ok(())
    }

    #[test]
    fn open_connection_enables_wal_and_busy_timeout() -> Result<()> {
        let state = TempDir::new()?;
        let store = KnowledgeStore::new(state.path());
        let conn = store.open_connection()?;

        let journal_mode: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        let busy_timeout_ms: i64 = conn.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;

        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
        assert!(busy_timeout_ms >= (crate::sqlite::SQLITE_BUSY_TIMEOUT_SECS as i64) * 1000);
        Ok(())
    }

    #[test]
    fn projects_entity_links_from_file_entities_and_located_in_edges() -> Result<()> {
        let state = TempDir::new()?;
        let store = KnowledgeStore::new(state.path());
        let _ = store.store_candidates(
            "session-1",
            1_000,
            &[KnowledgeFactCandidate {
                subject_type_hint: Some("symbol".to_string()),
                subject_aliases: vec!["wake-up".to_string()],
                object_entity: Some("src/api/v1/wakeup.rs".to_string()),
                object_type_hint: Some("file".to_string()),
                source_role: "developer".to_string(),
                entity_hints: vec![
                    "wake-up endpoint".to_string(),
                    "src/api/v1/wakeup.rs".to_string(),
                ],
                valid_from_ms: Some(1_000),
                ..candidate(
                    "wake-up endpoint",
                    "located_in",
                    "src/api/v1/wakeup.rs",
                    "The wake-up endpoint lives in src/api/v1/wakeup.rs.",
                )
            }],
        )?;

        let subject_links = store.entity_links_for_entity("wake-up endpoint", Some("file"), 10)?;
        assert_eq!(subject_links.total, 1);
        assert_eq!(subject_links.links.len(), 1);
        assert_eq!(subject_links.links[0].link_type, "file");
        assert_eq!(subject_links.links[0].target, "src/api/v1/wakeup.rs");

        let file_links = store.entity_links_for_entity("src/api/v1/wakeup.rs", Some("file"), 10)?;
        assert_eq!(file_links.total, 1);
        assert_eq!(file_links.links.len(), 1);
        assert_eq!(file_links.links[0].entity_name, "src/api/v1/wakeup.rs");
        assert_eq!(file_links.links[0].target, "src/api/v1/wakeup.rs");
        Ok(())
    }

    #[test]
    fn deletes_session_scoped_facts() -> Result<()> {
        let state = TempDir::new()?;
        let store = KnowledgeStore::new(state.path());
        let _ = store.store_candidates(
            "session-1",
            1_000,
            &[KnowledgeFactCandidate {
                subject_type_hint: Some("repo".to_string()),
                object_type_hint: Some("decision".to_string()),
                category: "decision".to_string(),
                source_role: "assistant".to_string(),
                source_ordinal: 1,
                entity_hints: vec!["wake-up".to_string()],
                valid_from_ms: Some(1_000),
                ..candidate(
                    "repo",
                    "decision",
                    "Ship wake-up context.",
                    "We decided to ship wake-up context.",
                )
            }],
        )?;
        assert_eq!(store.facts_for_session("session-1")?.len(), 1);
        assert_eq!(store.delete_facts_for_session("session-1")?, 1);
        assert!(store.facts_for_session("session-1")?.is_empty());
        let neighborhood = store.neighborhood_for_entity("repo", None, 10)?;
        assert_eq!(neighborhood.total, 0);
        let episodes = store.search_episodes("wake-up", None, 10, 0)?;
        assert_eq!(episodes.total, 0);
        Ok(())
    }

    #[test]
    fn deleting_one_edge_preserves_other_links_in_the_same_episode() -> Result<()> {
        let state = TempDir::new()?;
        let store = KnowledgeStore::new(state.path());
        let _ = store.store_candidates(
            "session-1",
            1_000,
            &[
                KnowledgeFactCandidate {
                    subject_type_hint: Some("symbol".to_string()),
                    subject_aliases: vec!["wake-up".to_string()],
                    object_entity: Some("src/api/v1/wakeup.rs".to_string()),
                    object_type_hint: Some("file".to_string()),
                    source_role: "assistant".to_string(),
                    entity_hints: vec!["wake-up endpoint".to_string()],
                    valid_from_ms: Some(1_000),
                    ..candidate(
                        "wake-up endpoint",
                        "located_in",
                        "src/api/v1/wakeup.rs",
                        "The wake-up endpoint lives in src/api/v1/wakeup.rs.",
                    )
                },
                KnowledgeFactCandidate {
                    subject_type_hint: Some("symbol".to_string()),
                    object_entity: Some("src/knowledge/db.rs".to_string()),
                    object_type_hint: Some("file".to_string()),
                    source_role: "assistant".to_string(),
                    source_ordinal: 1,
                    entity_hints: vec!["timeline_index".to_string()],
                    valid_from_ms: Some(1_000),
                    ..candidate(
                        "timeline_index",
                        "located_in",
                        "src/knowledge/db.rs",
                        "timeline_index lives in src/knowledge/db.rs.",
                    )
                },
            ],
        )?;

        let wake_edge = store.search_edges("wake-up endpoint", None, 10, 0)?;
        assert_eq!(wake_edge.total, 1);
        let deleted = store.delete_edge(&wake_edge.edges[0].edge_id)?;
        assert!(deleted.deleted);
        assert_eq!(deleted.deleted_entity_links, 1);

        let wake_links = store.entity_links_for_entity("wake-up endpoint", Some("file"), 10)?;
        assert_eq!(wake_links.total, 0);

        let timeline_links = store.entity_links_for_entity("timeline_index", Some("file"), 10)?;
        assert_eq!(timeline_links.total, 1);
        assert_eq!(timeline_links.links[0].target, "src/knowledge/db.rs");

        let episodes = store.search_episodes("timeline_index", None, 10, 0)?;
        assert_eq!(episodes.total, 1);
        let episode = store
            .episode_details(&episodes.episodes[0].episode_id, 10)?
            .expect("remaining edge should keep the episode record");
        assert_eq!(episode.total_edges, 1);
        Ok(())
    }

    #[test]
    fn custom_graph_relations_can_extend_the_builtin_ontology() -> Result<()> {
        let state = TempDir::new()?;
        let store = KnowledgeStore::new(state.path());
        let candidate = KnowledgeFactCandidate {
            subject_type_hint: Some("repo".to_string()),
            object_type_hint: Some("concept".to_string()),
            category: "workflow".to_string(),
            confidence: "medium".to_string(),
            source_role: "assistant".to_string(),
            entity_hints: vec!["repo".to_string()],
            valid_from_ms: Some(1_000),
            ..candidate(
                "repo",
                "implements",
                "temporal memory graph",
                "Repo implements the temporal memory graph roadmap.",
            )
        };

        let rejected = store.store_candidates("session-1", 1_000, &[candidate.clone()])?;
        assert!(rejected.is_empty());

        let graph_config = crate::config::MemoryConversationGraphConfig {
            strict_ontology_validation: true,
            entity_types: vec![],
            relation_types: vec![crate::config::MemoryConversationGraphRelationTypeConfig {
                name: "implements".to_string(),
                aliases: vec!["realizes".to_string()],
                subject_types: vec!["repo".to_string()],
                object_types: vec!["concept".to_string()],
                allow_literal_object: true,
                cardinality: None,
            }],
        };
        let stored = store.store_candidates_with_graph_config(
            "session-2",
            2_000,
            &[candidate],
            Some(&graph_config),
        )?;
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].relation, "implements");
        Ok(())
    }

    #[test]
    fn ontology_cardinality_invalidates_previous_active_edges() -> Result<()> {
        let state = TempDir::new()?;
        let store = KnowledgeStore::new(state.path());
        let first = KnowledgeFactCandidate {
            subject_type_hint: Some("symbol".to_string()),
            subject_aliases: vec!["wake-up".to_string()],
            object_entity: Some("src/api/v1/wakeup.rs".to_string()),
            object_type_hint: Some("file".to_string()),
            source_role: "developer".to_string(),
            entity_hints: vec!["wake-up endpoint".to_string()],
            valid_from_ms: Some(1_000),
            ..candidate(
                "wake-up endpoint",
                "located_in",
                "src/api/v1/wakeup.rs",
                "The wake-up endpoint lives in src/api/v1/wakeup.rs.",
            )
        };
        let second = KnowledgeFactCandidate {
            subject_type_hint: Some("symbol".to_string()),
            subject_aliases: vec!["wake-up".to_string()],
            object_entity: Some("src/api/v1/kg.rs".to_string()),
            object_type_hint: Some("file".to_string()),
            source_role: "developer".to_string(),
            source_ordinal: 1,
            entity_hints: vec!["wake-up endpoint".to_string()],
            valid_from_ms: Some(2_000),
            ..candidate(
                "wake-up endpoint",
                "located_in",
                "src/api/v1/kg.rs",
                "The wake-up endpoint moved to src/api/v1/kg.rs.",
            )
        };

        let _ = store.store_candidates("session-1", 1_000, &[first])?;
        let _ = store.store_candidates("session-2", 2_000, &[second])?;

        let query = store.query_facts("wake-up endpoint", Some("located_in"), 10, 0)?;
        assert_eq!(query.total, 2);
        let old = query
            .facts
            .iter()
            .find(|fact| fact.object_text == "src/api/v1/wakeup.rs")
            .expect("old edge should still be queryable");
        let new = query
            .facts
            .iter()
            .find(|fact| fact.object_text == "src/api/v1/kg.rs")
            .expect("replacement edge should be queryable");
        assert!(old.invalidated_at_ms.is_some());
        assert!(new.invalidated_at_ms.is_none());

        let conn = Connection::open(store.path())?;
        let invalidation_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM knowledge_edge_invalidations",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(invalidation_count, 1);
        Ok(())
    }
}
