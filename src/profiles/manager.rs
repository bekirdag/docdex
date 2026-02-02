use crate::profiles::{Agent, Preference, PreferenceCategory};
use crate::state_layout::StateLayout;
use anyhow::{Context, Result};
use fs4::FileExt;
use rusqlite::{params, Connection, OptionalExtension};
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

use super::db::{
    distance_to_score, embedding_to_json, encode_embedding, init_profile_db, ProfileDbInit,
};

#[derive(Debug, Clone)]
pub struct ProfileManager {
    conn: Arc<parking_lot::Mutex<Connection>>,
    embedding_dim: usize,
    schema_version: u32,
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
            lock_path,
        })
    }

    pub fn embedding_dim(&self) -> usize {
        self.embedding_dim
    }

    pub fn schema_version(&self) -> u32 {
        self.schema_version
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
                    "SELECT id, agent_id, content, category, last_updated
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
                ))
            })?;
            for row in rows {
                let (id, agent_id, content, category_raw, last_updated) = match row {
                    Ok(row) => row,
                    Err(_) => continue,
                };
                let Some(category) = parse_category(&category_raw) else {
                    continue;
                };
                preferences.push(Preference {
                    id,
                    agent_id,
                    content,
                    embedding: None,
                    category,
                    last_updated,
                });
            }
        } else {
            let mut stmt = conn
                .prepare(
                    "SELECT id, agent_id, content, category, last_updated
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
                ))
            })?;
            for row in rows {
                let (id, agent_id, content, category_raw, last_updated) = match row {
                    Ok(row) => row,
                    Err(_) => continue,
                };
                let Some(category) = parse_category(&category_raw) else {
                    continue;
                };
                preferences.push(Preference {
                    id,
                    agent_id,
                    content,
                    embedding: None,
                    category,
                    last_updated,
                });
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
                tx.execute(
                    "UPDATE preferences
                     SET agent_id = ?1, content = ?2, embedding = ?3, category = ?4, last_updated = ?5
                     WHERE id = ?6",
                    params![
                        pref.agent_id,
                        pref.content,
                        embedding_blob,
                        pref.category.to_string(),
                        pref.last_updated,
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
            tx.execute(
                "INSERT INTO preferences (id, agent_id, content, embedding, category, last_updated)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    pref.id,
                    pref.agent_id,
                    pref.content,
                    embedding_blob,
                    pref.category.to_string(),
                    pref.last_updated
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
        conn.execute(
            "INSERT INTO preferences (id, agent_id, content, embedding, category, last_updated)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                id,
                agent_id,
                content,
                embedding_blob,
                category.to_string(),
                last_updated
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
                "SELECT p.id, p.agent_id, p.content, p.category, p.last_updated, v.distance
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
                row.get::<_, f64>(5)?,
            ))
        })?;
        let mut results = Vec::new();
        for row in rows {
            let (id, agent_id, content, category_raw, last_updated, distance) = match row {
                Ok(row) => row,
                Err(_) => continue,
            };
            let Some(category) = parse_category(&category_raw) else {
                continue;
            };
            results.push(PreferenceSearchResult {
                preference: Preference {
                    id,
                    agent_id,
                    content,
                    embedding: None,
                    category,
                    last_updated,
                },
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
        conn.execute(
            "UPDATE preferences SET content = ?1, embedding = ?2, last_updated = ?3 WHERE id = ?4",
            params![new_content, embedding_blob, last_updated, preference_id],
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
    file: std::fs::File,
}

impl FileLock {
    fn acquire(path: &Path, shared: bool) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("open lock file {}", path.display()))?;
        if shared {
            file.lock_shared()
                .with_context(|| format!("lock shared {}", path.display()))?;
        } else {
            file.lock_exclusive()
                .with_context(|| format!("lock exclusive {}", path.display()))?;
        }
        Ok(Self { file })
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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
