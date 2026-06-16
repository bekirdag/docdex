use crate::profiles::{Agent, Preference, PreferenceCategory};
use crate::state_layout::StateLayout;
use anyhow::{anyhow, Context, Result};
use fs4::FileExt;
use rusqlite::{params, Connection, OptionalExtension};
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;
use uuid::Uuid;

use super::db::{
    distance_to_score, embedding_to_json, encode_embedding, init_profile_db, ProfileDbInit,
};

#[derive(Debug, Clone)]
pub struct ProfileManager {
    conn: Arc<parking_lot::Mutex<Connection>>,
    embedding_dim: usize,
    schema_version: u32,
    db_path: PathBuf,
    lock_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct PreferenceSearchResult {
    pub preference: Preference,
    pub score: f32,
}

#[derive(Debug, Clone)]
pub struct PreferenceRecall {
    pub id: String,
    pub content: String,
    pub last_updated: i64,
}

#[derive(Debug, Clone)]
pub struct ProfileImportSummary {
    pub agents: usize,
    pub inserted: usize,
    pub updated: usize,
    pub skipped: usize,
}

const PROFILE_LOCK_MAX_ATTEMPTS_ENV: &str = "DOCDEX_PROFILE_LOCK_MAX_ATTEMPTS";
const PROFILE_LOCK_RETRY_BASE_MS_ENV: &str = "DOCDEX_PROFILE_LOCK_RETRY_BASE_MS";
const DEFAULT_PROFILE_LOCK_MAX_ATTEMPTS: u32 = 5;
const DEFAULT_PROFILE_LOCK_RETRY_BASE_MS: u64 = 25;
const MIN_PROFILE_LOCK_MAX_ATTEMPTS: u32 = 1;
const MAX_PROFILE_LOCK_MAX_ATTEMPTS: u32 = 20;
const MIN_PROFILE_LOCK_RETRY_BASE_MS: u64 = 1;
const MAX_PROFILE_LOCK_RETRY_BASE_MS: u64 = 5_000;

#[derive(Debug, Clone)]
pub struct ProfileExportManifest {
    pub agents: Vec<Agent>,
    pub preferences: Vec<Preference>,
}

impl ProfileManager {
    pub fn new(base_dir: &Path, embedding_dim: usize) -> Result<Self> {
        let layout = StateLayout::new(base_dir.to_path_buf());
        layout.ensure_global_dirs()?;
        let db_path = layout.profiles_dir().join("main.db");
        let lock_path = layout.profiles_dir().join("profiles.lock");
        let ProfileDbInit {
            conn,
            embedding_dim: stored_dim,
            schema_version,
        } = init_profile_db(&db_path, Some(embedding_dim))?;
        let resolved = stored_dim.unwrap_or(embedding_dim);
        Ok(Self {
            conn: Arc::new(parking_lot::Mutex::new(conn)),
            embedding_dim: resolved,
            schema_version,
            db_path,
            lock_path,
        })
    }

    pub fn embedding_dim(&self) -> usize {
        self.embedding_dim
    }

    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn check_access(&self) -> Result<()> {
        let _file_lock = self.lock_exclusive()?;
        let _guard = self.conn.lock();
        Ok(())
    }

    pub fn create_agent(&self, id: &str, role: &str, created_at: i64) -> Result<()> {
        let _file_lock = self.lock_exclusive()?;
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO agents (id, role, created_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET role = excluded.role, created_at = excluded.created_at",
            params![id, role, created_at],
        )
        .context("upsert agent")?;
        Ok(())
    }

    pub fn get_agent(&self, id: &str) -> Result<Option<Agent>> {
        let _file_lock = self.lock_shared()?;
        let conn = self.conn.lock();
        let row = conn
            .query_row(
                "SELECT id, role, created_at FROM agents WHERE id = ?1",
                params![id],
                |row| {
                    Ok(Agent {
                        id: row.get(0)?,
                        role: row.get(1)?,
                        created_at: row.get(2)?,
                    })
                },
            )
            .optional()
            .context("get agent")?;
        Ok(row)
    }

    pub fn list_agents(&self) -> Result<Vec<Agent>> {
        let _file_lock = self.lock_shared()?;
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT id, role, created_at FROM agents ORDER BY created_at ASC, id ASC")
            .context("prepare list agents")?;
        let rows = stmt.query_map([], |row| {
            Ok(Agent {
                id: row.get(0)?,
                role: row.get(1)?,
                created_at: row.get(2)?,
            })
        })?;
        let mut agents = Vec::new();
        for row in rows {
            if let Ok(agent) = row {
                agents.push(agent);
            }
        }
        Ok(agents)
    }

    pub fn export_manifest(&self, agent_id: Option<&str>) -> Result<ProfileExportManifest> {
        Ok(ProfileExportManifest {
            agents: self.list_agents()?,
            preferences: self.list_preferences(agent_id)?,
        })
    }

    pub fn list_preferences(&self, agent_id: Option<&str>) -> Result<Vec<Preference>> {
        let _file_lock = self.lock_shared()?;
        let conn = self.conn.lock();
        let mut preferences = Vec::new();
        if let Some(agent_id) = agent_id {
            let mut stmt = conn
                .prepare(
                    "SELECT id, agent_id, content, category, last_updated,
                            embedding_provider, embedding_model, embedding_dim
                     FROM preferences
                     WHERE agent_id = ?1
                     ORDER BY last_updated DESC, id ASC",
                )
                .context("prepare list preferences")?;
            let rows = stmt.query_map(params![agent_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                ))
            })?;
            for row in rows {
                let (
                    id,
                    agent_id,
                    content,
                    category_raw,
                    last_updated,
                    embedding_provider,
                    embedding_model,
                    embedding_dim,
                ) = match row {
                    Ok(row) => row,
                    Err(_) => continue,
                };
                let Some(category) = parse_category(&category_raw) else {
                    continue;
                };
                preferences.push(preference_from_parts(
                    id,
                    agent_id,
                    content,
                    category,
                    last_updated,
                    embedding_provider,
                    embedding_model,
                    embedding_dim,
                ));
            }
        } else {
            let mut stmt = conn
                .prepare(
                    "SELECT id, agent_id, content, category, last_updated,
                            embedding_provider, embedding_model, embedding_dim
                     FROM preferences
                     ORDER BY last_updated DESC, id ASC",
                )
                .context("prepare list preferences")?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                ))
            })?;
            for row in rows {
                let (
                    id,
                    agent_id,
                    content,
                    category_raw,
                    last_updated,
                    embedding_provider,
                    embedding_model,
                    embedding_dim,
                ) = match row {
                    Ok(row) => row,
                    Err(_) => continue,
                };
                let Some(category) = parse_category(&category_raw) else {
                    continue;
                };
                preferences.push(preference_from_parts(
                    id,
                    agent_id,
                    content,
                    category,
                    last_updated,
                    embedding_provider,
                    embedding_model,
                    embedding_dim,
                ));
            }
        }
        Ok(preferences)
    }

    pub fn import_preferences(
        &self,
        agents: &[Agent],
        preferences: &[Preference],
    ) -> Result<ProfileImportSummary> {
        let _file_lock = self.lock_exclusive()?;
        let mut conn = self.conn.lock();
        let tx = conn
            .transaction()
            .context("start profile import transaction")?;

        for agent in agents {
            tx.execute(
                "INSERT INTO agents (id, role, created_at)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(id) DO UPDATE SET role = excluded.role, created_at = excluded.created_at",
                params![agent.id, agent.role, agent.created_at],
            )
            .context("upsert agent during import")?;
        }

        let mut inserted = 0usize;
        let mut updated = 0usize;
        let mut skipped = 0usize;

        for pref in preferences {
            let Some(embedding) = pref.embedding.as_ref() else {
                anyhow::bail!("preference {} missing embedding for import", pref.id);
            };
            if embedding.len() != self.embedding_dim {
                anyhow::bail!(
                    "embedding dimension mismatch: expected {}, got {}",
                    self.embedding_dim,
                    embedding.len()
                );
            }

            let existing_last = tx
                .query_row(
                    "SELECT last_updated FROM preferences WHERE id = ?1",
                    params![pref.id],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .context("lookup preference for import")?;

            if let Some(existing) = existing_last {
                if pref.last_updated <= existing {
                    skipped += 1;
                    continue;
                }
                let embedding_blob = encode_embedding(embedding);
                let embedding_provider =
                    normalize_metadata_text(pref.embedding_provider.as_deref());
                let embedding_model = normalize_metadata_text(pref.embedding_model.as_deref());
                tx.execute(
                    "UPDATE preferences
                     SET agent_id = ?1,
                         content = ?2,
                         embedding = ?3,
                         category = ?4,
                         last_updated = ?5,
                         embedding_provider = ?6,
                         embedding_model = ?7,
                         embedding_dim = ?8
                     WHERE id = ?9",
                    params![
                        pref.agent_id,
                        pref.content,
                        embedding_blob,
                        pref.category.to_string(),
                        pref.last_updated,
                        embedding_provider.as_deref(),
                        embedding_model.as_deref(),
                        embedding.len() as i64,
                        pref.id
                    ],
                )
                .context("update preference during import")?;
                let embedding_json = embedding_to_json(embedding).context("serialize embedding")?;
                tx.execute(
                    "UPDATE preferences_vec
                     SET embedding = ?1
                     WHERE rowid = (SELECT rowid FROM preferences WHERE id = ?2)",
                    params![embedding_json, pref.id],
                )
                .context("update preference vector during import")?;
                updated += 1;
                continue;
            }

            let embedding_blob = encode_embedding(embedding);
            let embedding_provider = normalize_metadata_text(pref.embedding_provider.as_deref());
            let embedding_model = normalize_metadata_text(pref.embedding_model.as_deref());
            tx.execute(
                "INSERT INTO preferences (
                    id, agent_id, content, embedding, category, last_updated,
                    embedding_provider, embedding_model, embedding_dim
                 )
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    pref.id,
                    pref.agent_id,
                    pref.content,
                    embedding_blob,
                    pref.category.to_string(),
                    pref.last_updated,
                    embedding_provider.as_deref(),
                    embedding_model.as_deref(),
                    embedding.len() as i64
                ],
            )
            .context("insert preference during import")?;
            let rowid = tx.last_insert_rowid();
            let embedding_json = embedding_to_json(embedding).context("serialize embedding")?;
            tx.execute(
                "INSERT INTO preferences_vec (rowid, embedding) VALUES (?1, ?2)",
                params![rowid, embedding_json],
            )
            .context("insert preference vector during import")?;
            inserted += 1;
        }

        tx.commit().context("commit profile import transaction")?;
        Ok(ProfileImportSummary {
            agents: agents.len(),
            inserted,
            updated,
            skipped,
        })
    }

    pub fn add_preference(
        &self,
        agent_id: &str,
        content: &str,
        embedding: &[f32],
        category: PreferenceCategory,
        last_updated: i64,
    ) -> Result<Preference> {
        self.add_preference_with_embedding_metadata(
            agent_id,
            content,
            embedding,
            category,
            last_updated,
            None,
            None,
        )
    }

    pub fn add_preference_with_embedding_metadata(
        &self,
        agent_id: &str,
        content: &str,
        embedding: &[f32],
        category: PreferenceCategory,
        last_updated: i64,
        embedding_provider: Option<&str>,
        embedding_model: Option<&str>,
    ) -> Result<Preference> {
        if embedding.len() != self.embedding_dim {
            anyhow::bail!(
                "embedding dimension mismatch: expected {}, got {}",
                self.embedding_dim,
                embedding.len()
            );
        }
        let _file_lock = self.lock_exclusive()?;
        let conn = self.conn.lock();
        let id = Uuid::new_v4().to_string();
        let embedding_blob = encode_embedding(embedding);
        let embedding_provider = normalize_metadata_text(embedding_provider);
        let embedding_model = normalize_metadata_text(embedding_model);
        conn.execute(
            "INSERT INTO preferences (
                id, agent_id, content, embedding, category, last_updated,
                embedding_provider, embedding_model, embedding_dim
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                id,
                agent_id,
                content,
                embedding_blob,
                category.to_string(),
                last_updated,
                embedding_provider.as_deref(),
                embedding_model.as_deref(),
                embedding.len() as i64
            ],
        )
        .context("insert preference")?;
        let rowid = conn.last_insert_rowid();
        let embedding_json = embedding_to_json(embedding).context("serialize embedding")?;
        conn.execute(
            "INSERT INTO preferences_vec (rowid, embedding) VALUES (?1, ?2)",
            params![rowid, embedding_json],
        )
        .context("insert preference vector")?;
        Ok(Preference {
            id,
            agent_id: agent_id.to_string(),
            content: content.to_string(),
            embedding: None,
            embedding_provider,
            embedding_model,
            embedding_dim: Some(embedding.len()),
            category,
            last_updated,
        })
    }

    pub fn search_preferences(
        &self,
        agent_id: &str,
        query_embedding: &[f32],
        top_k: usize,
    ) -> Result<Vec<PreferenceSearchResult>> {
        if query_embedding.len() != self.embedding_dim {
            anyhow::bail!(
                "embedding dimension mismatch: expected {}, got {}",
                self.embedding_dim,
                query_embedding.len()
            );
        }
        let _file_lock = self.lock_shared()?;
        let conn = self.conn.lock();
        let query_json = embedding_to_json(query_embedding).context("serialize query embedding")?;
        let mut stmt = conn
            .prepare(
                "SELECT p.id, p.agent_id, p.content, p.category, p.last_updated,
                        p.embedding_provider, p.embedding_model, p.embedding_dim,
                        v.distance
                 FROM preferences_vec v
                 JOIN preferences p ON p.rowid = v.rowid
                 WHERE p.agent_id = ?1
                   AND v.rowid IN (SELECT rowid FROM preferences WHERE agent_id = ?1)
                   AND v.embedding MATCH ?2 AND k = ?3
                 ORDER BY v.distance ASC, p.last_updated DESC, p.id ASC",
            )
            .context("prepare preference search")?;
        let rows = stmt.query_map(params![agent_id, query_json, top_k as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, f64>(8)?,
            ))
        })?;
        let mut results = Vec::new();
        for row in rows {
            let (
                id,
                agent_id,
                content,
                category_raw,
                last_updated,
                embedding_provider,
                embedding_model,
                embedding_dim,
                distance,
            ) = match row {
                Ok(row) => row,
                Err(_) => continue,
            };
            let Some(category) = parse_category(&category_raw) else {
                continue;
            };
            results.push(PreferenceSearchResult {
                preference: preference_from_parts(
                    id,
                    agent_id,
                    content,
                    category,
                    last_updated,
                    embedding_provider,
                    embedding_model,
                    embedding_dim,
                ),
                score: distance_to_score(distance),
            });
        }
        results.truncate(top_k.max(1));
        Ok(results)
    }

    pub fn search_preferences_for_evolution(
        &self,
        agent_id: &str,
        query_embedding: &[f32],
        top_k: usize,
    ) -> Result<Vec<PreferenceRecall>> {
        let debug_recall = cfg!(test)
            && std::env::var("DOCDEX_DEBUG_PROFILE_RECALL")
                .map(|value| value.trim() == "1")
                .unwrap_or(false);
        if query_embedding.len() != self.embedding_dim {
            anyhow::bail!(
                "embedding dimension mismatch: expected {}, got {}",
                self.embedding_dim,
                query_embedding.len()
            );
        }
        let _file_lock = self.lock_shared()?;
        let conn = self.conn.lock();
        if debug_recall {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM preferences WHERE agent_id = ?1",
                    params![agent_id],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            let vec_count: i64 = conn
                .query_row("SELECT COUNT(*) FROM preferences_vec", [], |row| row.get(0))
                .unwrap_or(0);
            eprintln!(
                "[profiles] recall agent={agent_id} prefs={count} vecs={vec_count} k={top_k}"
            );
        }
        let query_json = embedding_to_json(query_embedding).context("serialize query embedding")?;
        let mut stmt = conn
            .prepare(
                "SELECT p.id, p.content, p.last_updated, v.distance\n                 FROM preferences_vec v\n                 JOIN preferences p ON p.rowid = v.rowid\n                 WHERE p.agent_id = ?1\n                   AND v.rowid IN (SELECT rowid FROM preferences WHERE agent_id = ?1)\n                   AND v.embedding MATCH ?2 AND k = ?3\n                 ORDER BY v.distance ASC, p.last_updated DESC, p.id ASC",
            )
            .context("prepare preference recall")?;
        let rows = stmt.query_map(params![agent_id, query_json, top_k as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        let mut results = Vec::new();
        for row in rows {
            let (id, content, last_updated) = match row {
                Ok(row) => row,
                Err(_) => continue,
            };
            results.push(PreferenceRecall {
                id,
                content,
                last_updated,
            });
        }
        if debug_recall {
            eprintln!("[profiles] recall results={}", results.len());
        }
        results.truncate(top_k.max(1));
        Ok(results)
    }

    pub fn update_preference(
        &self,
        preference_id: &str,
        new_content: &str,
        embedding: &[f32],
        last_updated: i64,
    ) -> Result<()> {
        self.update_preference_with_embedding_metadata(
            preference_id,
            new_content,
            embedding,
            last_updated,
            None,
            None,
        )
    }

    pub fn update_preference_with_embedding_metadata(
        &self,
        preference_id: &str,
        new_content: &str,
        embedding: &[f32],
        last_updated: i64,
        embedding_provider: Option<&str>,
        embedding_model: Option<&str>,
    ) -> Result<()> {
        if embedding.len() != self.embedding_dim {
            anyhow::bail!(
                "embedding dimension mismatch: expected {}, got {}",
                self.embedding_dim,
                embedding.len()
            );
        }
        let _file_lock = self.lock_exclusive()?;
        let conn = self.conn.lock();
        let rowid: Option<i64> = conn
            .query_row(
                "SELECT rowid FROM preferences WHERE id = ?1",
                params![preference_id],
                |row| row.get(0),
            )
            .optional()
            .context("lookup preference rowid")?;
        let Some(rowid) = rowid else {
            anyhow::bail!("preference not found");
        };
        let embedding_blob = encode_embedding(embedding);
        let embedding_provider = normalize_metadata_text(embedding_provider);
        let embedding_model = normalize_metadata_text(embedding_model);
        conn.execute(
            "UPDATE preferences
             SET content = ?1,
                 embedding = ?2,
                 last_updated = ?3,
                 embedding_provider = ?4,
                 embedding_model = ?5,
                 embedding_dim = ?6
             WHERE id = ?7",
            params![
                new_content,
                embedding_blob,
                last_updated,
                embedding_provider.as_deref(),
                embedding_model.as_deref(),
                embedding.len() as i64,
                preference_id
            ],
        )
        .context("update preference")?;
        let embedding_json = embedding_to_json(embedding).context("serialize embedding")?;
        let updated = conn
            .execute(
                "UPDATE preferences_vec SET embedding = ?1 WHERE rowid = ?2",
                params![embedding_json, rowid],
            )
            .context("update preference vector")?;
        if updated == 0 {
            conn.execute(
                "INSERT INTO preferences_vec (rowid, embedding) VALUES (?1, ?2)",
                params![rowid, embedding_json],
            )
            .context("insert preference vector")?;
        }
        Ok(())
    }

    pub fn delete_preference(&self, preference_id: &str) -> Result<bool> {
        let _file_lock = self.lock_exclusive()?;
        let conn = self.conn.lock();
        let rowid: Option<i64> = conn
            .query_row(
                "SELECT rowid FROM preferences WHERE id = ?1",
                params![preference_id],
                |row| row.get(0),
            )
            .optional()
            .context("lookup preference rowid")?;
        let Some(rowid) = rowid else {
            return Ok(false);
        };
        conn.execute(
            "DELETE FROM preferences WHERE id = ?1",
            params![preference_id],
        )
        .context("delete preference")?;
        conn.execute(
            "DELETE FROM preferences_vec WHERE rowid = ?1",
            params![rowid],
        )
        .context("delete preference vector")?;
        Ok(true)
    }

    fn lock_shared(&self) -> Result<FileLock> {
        FileLock::acquire(&self.lock_path, true)
    }

    fn lock_exclusive(&self) -> Result<FileLock> {
        FileLock::acquire(&self.lock_path, false)
    }
}

fn parse_category(raw: &str) -> Option<PreferenceCategory> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "style" => Some(PreferenceCategory::Style),
        "tooling" => Some(PreferenceCategory::Tooling),
        "constraint" => Some(PreferenceCategory::Constraint),
        "workflow" => Some(PreferenceCategory::Workflow),
        _ => None,
    }
}

fn preference_from_parts(
    id: String,
    agent_id: String,
    content: String,
    category: PreferenceCategory,
    last_updated: i64,
    embedding_provider: Option<String>,
    embedding_model: Option<String>,
    embedding_dim: Option<i64>,
) -> Preference {
    Preference {
        id,
        agent_id,
        content,
        embedding: None,
        embedding_provider: normalize_metadata_text(embedding_provider.as_deref()),
        embedding_model: normalize_metadata_text(embedding_model.as_deref()),
        embedding_dim: normalize_metadata_dim(embedding_dim),
        category,
        last_updated,
    }
}

fn normalize_metadata_text(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn normalize_metadata_dim(value: Option<i64>) -> Option<usize> {
    value
        .and_then(|dim| usize::try_from(dim).ok())
        .filter(|dim| *dim > 0)
}

impl ToString for PreferenceCategory {
    fn to_string(&self) -> String {
        match self {
            PreferenceCategory::Style => "style".to_string(),
            PreferenceCategory::Tooling => "tooling".to_string(),
            PreferenceCategory::Constraint => "constraint".to_string(),
            PreferenceCategory::Workflow => "workflow".to_string(),
        }
    }
}

struct FileLock {
    file: Option<std::fs::File>,
    locked: bool,
}

impl FileLock {
    fn acquire(path: &Path, shared: bool) -> Result<Self> {
        let retry_policy = profile_lock_retry_policy_from_env();
        for attempt in 1..=retry_policy.max_attempts {
            let file = match OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .open(path)
            {
                Ok(file) => Some(file),
                Err(err) => {
                    if should_ignore_lock_error(&err) {
                        warn!(
                            error = ?err,
                            path = %path.display(),
                            "profile lock unavailable; proceeding without file lock"
                        );
                        return Ok(Self {
                            file: None,
                            locked: false,
                        });
                    }
                    if is_retryable_lock_error(&err) && attempt < retry_policy.max_attempts {
                        let backoff_ms = retry_policy.backoff_for_attempt(attempt);
                        warn!(
                            error = ?err,
                            path = %path.display(),
                            attempt,
                            max_attempts = retry_policy.max_attempts,
                            backoff_ms,
                            operation = "open",
                            error_class = lock_error_class(&err),
                            "profile lock transient error; retrying"
                        );
                        std::thread::sleep(Duration::from_millis(backoff_ms));
                        continue;
                    }
                    if is_retryable_lock_error(&err) {
                        return Err(retry_exhausted_error("open lock file", path, attempt, &err));
                    }
                    return Err(err).with_context(|| format!("open lock file {}", path.display()));
                }
            };

            if let Some(file_ref) = file.as_ref() {
                let lock_result = if shared {
                    file_ref.lock_shared()
                } else {
                    file_ref.lock_exclusive()
                };
                if let Err(err) = lock_result {
                    if should_ignore_lock_error(&err) {
                        warn!(
                            error = ?err,
                            path = %path.display(),
                            "profile lock unavailable; proceeding without file lock"
                        );
                        return Ok(Self {
                            file,
                            locked: false,
                        });
                    }
                    if is_retryable_lock_error(&err) && attempt < retry_policy.max_attempts {
                        let backoff_ms = retry_policy.backoff_for_attempt(attempt);
                        warn!(
                            error = ?err,
                            path = %path.display(),
                            attempt,
                            max_attempts = retry_policy.max_attempts,
                            backoff_ms,
                            operation = if shared { "lock_shared" } else { "lock_exclusive" },
                            error_class = lock_error_class(&err),
                            "profile lock transient error; retrying"
                        );
                        std::thread::sleep(Duration::from_millis(backoff_ms));
                        continue;
                    }
                    if is_retryable_lock_error(&err) {
                        return Err(retry_exhausted_error(
                            if shared {
                                "lock shared"
                            } else {
                                "lock exclusive"
                            },
                            path,
                            attempt,
                            &err,
                        ));
                    }
                    return Err(err).with_context(|| {
                        format!(
                            "{} {}",
                            if shared {
                                "lock shared"
                            } else {
                                "lock exclusive"
                            },
                            path.display()
                        )
                    });
                }
            }
            return Ok(Self { file, locked: true });
        }

        Err(anyhow!(
            "profile lock retry policy exhausted unexpectedly for {}",
            path.display()
        ))
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        if self.locked {
            if let Some(file) = self.file.as_ref() {
                let _ = file.unlock();
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ProfileLockRetryPolicy {
    max_attempts: u32,
    base_backoff_ms: u64,
}

impl ProfileLockRetryPolicy {
    fn backoff_for_attempt(self, attempt: u32) -> u64 {
        self.base_backoff_ms.saturating_mul(u64::from(attempt))
    }
}

fn profile_lock_retry_policy_from_env() -> ProfileLockRetryPolicy {
    let max_attempts = parse_profile_lock_max_attempts(
        std::env::var(PROFILE_LOCK_MAX_ATTEMPTS_ENV).ok().as_deref(),
    );
    let base_backoff_ms = parse_profile_lock_retry_base_ms(
        std::env::var(PROFILE_LOCK_RETRY_BASE_MS_ENV)
            .ok()
            .as_deref(),
    );
    ProfileLockRetryPolicy {
        max_attempts,
        base_backoff_ms,
    }
}

fn parse_profile_lock_max_attempts(raw: Option<&str>) -> u32 {
    let Some(raw) = raw else {
        return DEFAULT_PROFILE_LOCK_MAX_ATTEMPTS;
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return DEFAULT_PROFILE_LOCK_MAX_ATTEMPTS;
    }
    let Ok(parsed) = trimmed.parse::<u32>() else {
        return DEFAULT_PROFILE_LOCK_MAX_ATTEMPTS;
    };
    if parsed == 0 {
        return DEFAULT_PROFILE_LOCK_MAX_ATTEMPTS;
    }
    parsed.clamp(MIN_PROFILE_LOCK_MAX_ATTEMPTS, MAX_PROFILE_LOCK_MAX_ATTEMPTS)
}

fn parse_profile_lock_retry_base_ms(raw: Option<&str>) -> u64 {
    let Some(raw) = raw else {
        return DEFAULT_PROFILE_LOCK_RETRY_BASE_MS;
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return DEFAULT_PROFILE_LOCK_RETRY_BASE_MS;
    }
    let Ok(parsed) = trimmed.parse::<u64>() else {
        return DEFAULT_PROFILE_LOCK_RETRY_BASE_MS;
    };
    if parsed == 0 {
        return DEFAULT_PROFILE_LOCK_RETRY_BASE_MS;
    }
    parsed.clamp(
        MIN_PROFILE_LOCK_RETRY_BASE_MS,
        MAX_PROFILE_LOCK_RETRY_BASE_MS,
    )
}

fn should_ignore_lock_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::Unsupported | ErrorKind::PermissionDenied | ErrorKind::ReadOnlyFilesystem
    )
}

fn is_retryable_lock_error(err: &std::io::Error) -> bool {
    if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) {
        return true;
    }
    match err.raw_os_error() {
        Some(code) if code == os_error_emfile() || code == os_error_enfile() => true,
        _ => false,
    }
}

fn lock_error_class(err: &std::io::Error) -> &'static str {
    if should_ignore_lock_error(err) {
        "ignore"
    } else if is_retryable_lock_error(err) {
        "retryable"
    } else {
        "fatal"
    }
}

fn retry_exhausted_error(
    operation: &str,
    path: &Path,
    attempts: u32,
    err: &std::io::Error,
) -> anyhow::Error {
    anyhow!(
        "{} {} failed after {} attempts; error_class={} kind={:?} os_error={:?}: {}",
        operation,
        path.display(),
        attempts,
        lock_error_class(err),
        err.kind(),
        err.raw_os_error(),
        err
    )
}

#[cfg(unix)]
fn os_error_emfile() -> i32 {
    nix::libc::EMFILE
}

#[cfg(not(unix))]
fn os_error_emfile() -> i32 {
    24
}

#[cfg(unix)]
fn os_error_enfile() -> i32 {
    nix::libc::ENFILE
}

#[cfg(not(unix))]
fn os_error_enfile() -> i32 {
    23
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parse_profile_lock_max_attempts_defaults_and_clamps() {
        assert_eq!(
            parse_profile_lock_max_attempts(None),
            DEFAULT_PROFILE_LOCK_MAX_ATTEMPTS
        );
        assert_eq!(
            parse_profile_lock_max_attempts(Some("")),
            DEFAULT_PROFILE_LOCK_MAX_ATTEMPTS
        );
        assert_eq!(
            parse_profile_lock_max_attempts(Some("abc")),
            DEFAULT_PROFILE_LOCK_MAX_ATTEMPTS
        );
        assert_eq!(
            parse_profile_lock_max_attempts(Some("0")),
            DEFAULT_PROFILE_LOCK_MAX_ATTEMPTS
        );
        assert_eq!(
            parse_profile_lock_max_attempts(Some("1")),
            MIN_PROFILE_LOCK_MAX_ATTEMPTS
        );
        assert_eq!(
            parse_profile_lock_max_attempts(Some("200")),
            MAX_PROFILE_LOCK_MAX_ATTEMPTS
        );
    }

    #[test]
    fn parse_profile_lock_retry_base_ms_defaults_and_clamps() {
        assert_eq!(
            parse_profile_lock_retry_base_ms(None),
            DEFAULT_PROFILE_LOCK_RETRY_BASE_MS
        );
        assert_eq!(
            parse_profile_lock_retry_base_ms(Some("")),
            DEFAULT_PROFILE_LOCK_RETRY_BASE_MS
        );
        assert_eq!(
            parse_profile_lock_retry_base_ms(Some("abc")),
            DEFAULT_PROFILE_LOCK_RETRY_BASE_MS
        );
        assert_eq!(
            parse_profile_lock_retry_base_ms(Some("0")),
            DEFAULT_PROFILE_LOCK_RETRY_BASE_MS
        );
        assert_eq!(
            parse_profile_lock_retry_base_ms(Some("1")),
            MIN_PROFILE_LOCK_RETRY_BASE_MS
        );
        assert_eq!(
            parse_profile_lock_retry_base_ms(Some("999999")),
            MAX_PROFILE_LOCK_RETRY_BASE_MS
        );
    }

    #[test]
    fn retryable_lock_errors_cover_kinds_and_fd_os_codes() {
        assert!(is_retryable_lock_error(&std::io::Error::new(
            ErrorKind::WouldBlock,
            "busy"
        )));
        assert!(is_retryable_lock_error(&std::io::Error::new(
            ErrorKind::Interrupted,
            "signal"
        )));
        assert!(is_retryable_lock_error(&std::io::Error::from_raw_os_error(
            os_error_emfile()
        )));
        assert!(is_retryable_lock_error(&std::io::Error::from_raw_os_error(
            os_error_enfile()
        )));
        assert!(!is_retryable_lock_error(&std::io::Error::new(
            ErrorKind::NotFound,
            "missing"
        )));
    }

    #[test]
    fn retry_exhausted_error_includes_path_attempts_and_class() {
        let path = Path::new("/tmp/profiles.lock");
        let err = std::io::Error::new(ErrorKind::WouldBlock, "busy");
        let message = retry_exhausted_error("lock shared", path, 5, &err).to_string();

        assert!(message.contains("lock shared"));
        assert!(message.contains(path.to_string_lossy().as_ref()));
        assert!(message.contains("5 attempts"));
        assert!(message.contains("error_class=retryable"));
    }

    #[test]
    fn recall_orders_by_distance_then_recency() -> Result<()> {
        let dir = tempdir()?;
        let manager = ProfileManager::new(dir.path(), 2)?;
        manager.create_agent("agent", "test", 1)?;

        let newer = manager.add_preference(
            "agent",
            "newer",
            &[0.0_f32, 0.0_f32],
            PreferenceCategory::Style,
            20,
        )?;
        let older = manager.add_preference(
            "agent",
            "older",
            &[0.0_f32, 0.0_f32],
            PreferenceCategory::Style,
            10,
        )?;
        let farther = manager.add_preference(
            "agent",
            "farther",
            &[1.0_f32, 1.0_f32],
            PreferenceCategory::Style,
            30,
        )?;

        let results = manager.search_preferences_for_evolution("agent", &[0.0_f32, 0.0_f32], 3)?;
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].id, newer.id);
        assert_eq!(results[1].id, older.id);
        assert_eq!(results[2].id, farther.id);
        Ok(())
    }

    #[test]
    fn add_preference_inserts_row() -> Result<()> {
        let dir = tempdir()?;
        let manager = ProfileManager::new(dir.path(), 2)?;
        manager.create_agent("agent-add", "test", 1)?;
        let added = manager.add_preference(
            "agent-add",
            "Prefer Zod",
            &[0.0_f32, 0.0_f32],
            PreferenceCategory::Tooling,
            5,
        )?;
        let results = manager.search_preferences("agent-add", &[0.0, 0.0], 5)?;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].preference.id, added.id);
        Ok(())
    }

    #[test]
    fn add_preference_records_embedding_metadata() -> Result<()> {
        let dir = tempdir()?;
        let manager = ProfileManager::new(dir.path(), 2)?;
        manager.create_agent("agent-metadata", "test", 1)?;
        let added = manager.add_preference_with_embedding_metadata(
            "agent-metadata",
            "Use local embeddings",
            &[0.0_f32, 0.0_f32],
            PreferenceCategory::Tooling,
            5,
            Some("vllm"),
            Some("bge-m3"),
        )?;

        assert_eq!(added.embedding_provider.as_deref(), Some("vllm"));
        assert_eq!(added.embedding_model.as_deref(), Some("bge-m3"));
        assert_eq!(added.embedding_dim, Some(2));

        let row = {
            let conn = manager.conn.lock();
            conn.query_row(
                "SELECT embedding_provider, embedding_model, embedding_dim FROM preferences WHERE id = ?1",
                params![added.id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )?
        };
        assert_eq!(row, ("vllm".to_string(), "bge-m3".to_string(), 2));

        let listed = manager.list_preferences(Some("agent-metadata"))?;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].embedding_provider.as_deref(), Some("vllm"));
        assert_eq!(listed[0].embedding_model.as_deref(), Some("bge-m3"));
        assert_eq!(listed[0].embedding_dim, Some(2));

        let results = manager.search_preferences("agent-metadata", &[0.0, 0.0], 5)?;
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].preference.embedding_provider.as_deref(),
            Some("vllm")
        );
        assert_eq!(
            results[0].preference.embedding_model.as_deref(),
            Some("bge-m3")
        );
        assert_eq!(results[0].preference.embedding_dim, Some(2));

        let manifest = manager.export_manifest(Some("agent-metadata"))?;
        assert_eq!(manifest.preferences.len(), 1);
        assert_eq!(
            manifest.preferences[0].embedding_provider.as_deref(),
            Some("vllm")
        );
        assert_eq!(
            manifest.preferences[0].embedding_model.as_deref(),
            Some("bge-m3")
        );
        assert_eq!(manifest.preferences[0].embedding_dim, Some(2));
        Ok(())
    }

    #[test]
    fn update_preference_overwrites_content() -> Result<()> {
        let dir = tempdir()?;
        let manager = ProfileManager::new(dir.path(), 2)?;
        manager.create_agent("agent-update", "test", 1)?;
        let added = manager.add_preference(
            "agent-update",
            "Prefer Jest",
            &[0.0_f32, 0.0_f32],
            PreferenceCategory::Tooling,
            10,
        )?;
        manager.update_preference(&added.id, "Prefer Vitest", &[0.0, 0.0], 20)?;
        let results = manager.search_preferences("agent-update", &[0.0, 0.0], 5)?;
        assert_eq!(results[0].preference.content, "Prefer Vitest");
        Ok(())
    }

    #[test]
    fn last_updated_is_monotonic_on_update() -> Result<()> {
        let dir = tempdir()?;
        let manager = ProfileManager::new(dir.path(), 2)?;
        manager.create_agent("agent-time", "test", 1)?;
        let added = manager.add_preference(
            "agent-time",
            "Prefer Jest",
            &[0.0_f32, 0.0_f32],
            PreferenceCategory::Tooling,
            10,
        )?;
        manager.update_preference(&added.id, "Prefer Vitest", &[0.0, 0.0], 30)?;
        let results = manager.search_preferences("agent-time", &[0.0, 0.0], 5)?;
        assert_eq!(results[0].preference.last_updated, 30);
        Ok(())
    }
}
