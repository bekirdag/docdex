use crate::memory::ops::{
    apply_supersedes_penalty, mark_superseded_metadata, metadata_is_superseded,
    normalize_supersedes_metadata, MemoryCandidate, MemoryItem,
};
use anyhow::{Context, Result};
use fs4::FileExt;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension};
use serde::Serialize;
use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Once;
use tracing::warn;
use uuid::Uuid;

const MEMORY_WARN_ROWS: i64 = 50_000;
const MEMORY_PRUNE_TARGET_ROWS: i64 = 45_000;
const MEMORY_META_EMBED_DIM: &str = "embedding_dim";
const MEMORY_META_SCHEMA_VERSION: &str = "schema_version";
const MEMORY_SCHEMA_VERSION: u32 = 1;
const MEMORY_COMPACT_CHUNK: usize = 500;
static MEMORY_WARNED: AtomicBool = AtomicBool::new(false);
static SQLITE_VEC_INIT: Once = Once::new();

#[derive(Clone)]
pub struct MemoryStore {
    path: PathBuf,
    lock: Arc<parking_lot::Mutex<()>>,
    lock_path: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryCompactSummary {
    pub total: usize,
    pub superseded: usize,
    pub deleted: usize,
    pub dry_run: bool,
}

impl MemoryStore {
    pub fn new(state_dir: &Path) -> Self {
        let _ = crate::memory::ensure_repo_state_dir(state_dir);
        let path = crate::memory::memory_path(state_dir);
        let lock_dir = crate::memory::locks_dir_from_state_dir(state_dir);
        let _ = crate::state_layout::ensure_state_dir_secure(&lock_dir);
        let lock_path = crate::memory::memory_lock_path(state_dir);
        Self {
            path,
            lock: Arc::new(parking_lot::Mutex::new(())),
            lock_path,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn open_connection(&self, embedding_dim: Option<usize>) -> Result<(Connection, Option<usize>)> {
        ensure_vec_extension_loaded()?;
        let conn = crate::sqlite::open_rw_create_full_mutex(&self.path, "memory")?;
        let stored_dim = ensure_schema(&conn, embedding_dim)?;
        Ok((conn, stored_dim))
    }

    pub fn check_access(&self) -> Result<()> {
        let _guard = self.lock.lock();
        let _file_lock = self.lock_exclusive()?;
        let _ = self.open_connection(None)?;
        Ok(())
    }

    pub fn embedding_dim(&self) -> Result<Option<usize>> {
        let _guard = self.lock.lock();
        let _file_lock = self.lock_shared()?;
        let (_, stored_dim) = self.open_connection(None)?;
        Ok(stored_dim)
    }

    pub fn store(
        &self,
        content: &str,
        embedding: &[f32],
        metadata: Value,
        created_at_ms: i64,
    ) -> Result<(Uuid, i64)> {
        let _guard = self.lock.lock();
        let _file_lock = self.lock_exclusive()?;
        let id = Uuid::new_v4();
        let embedding_blob = encode_embedding(embedding);
        let (metadata, supersedes) = normalize_supersedes_metadata(metadata, created_at_ms);
        let metadata_json = serde_json::to_string(&metadata).context("serialize metadata")?;
        let (mut conn, _) = self.open_connection(Some(embedding.len()))?;
        conn.execute(
            "INSERT INTO memories (id, content, embedding, created_at, metadata)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                id.to_string(),
                content,
                embedding_blob,
                created_at_ms,
                metadata_json
            ],
        )
        .context("insert memory record")?;
        let rowid = conn.last_insert_rowid();
        let embedding_json = embedding_to_json(embedding).context("serialize embedding")?;
        conn.execute(
            "INSERT INTO memory_vec (rowid, embedding) VALUES (?1, ?2)",
            params![rowid, embedding_json],
        )
        .context("insert memory vector")?;
        if !supersedes.is_empty() {
            let superseded_by = id.to_string();
            let _ = self.update_superseded_metadata(
                &mut conn,
                &supersedes,
                &superseded_by,
                created_at_ms,
            )?;
        }
        self.enforce_guardrails(&mut conn)?;
        Ok((id, created_at_ms))
    }

    pub fn recall_candidates(
        &self,
        query_embedding: &[f32],
        top_k: usize,
    ) -> Result<Vec<MemoryCandidate>> {
        let _guard = self.lock.lock();
        let _file_lock = self.lock_shared()?;
        let (conn, stored_dim) = self.open_connection(None)?;
        let Some(expected_dim) = stored_dim else {
            return Ok(Vec::new());
        };
        if expected_dim != query_embedding.len() {
            return Err(anyhow::anyhow!(
                "embedding dimension mismatch: expected {expected_dim}, got {}",
                query_embedding.len()
            ));
        }
        let query_json = embedding_to_json(query_embedding).context("serialize query embedding")?;
        let mut stmt = conn
            .prepare(
                "SELECT m.id, m.content, m.created_at, m.metadata, v.distance
                 FROM memory_vec v
                 JOIN memories m ON m.rowid = v.rowid
                 WHERE v.embedding MATCH ?1 AND k = ?2
                 ORDER BY v.distance ASC, m.created_at DESC, m.id ASC",
            )
            .context("prepare memory recall")?;
        let rows = stmt.query_map(params![query_json, top_k as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, f64>(4)?,
            ))
        })?;
        let mut scored: Vec<MemoryCandidate> = Vec::new();

        for row in rows {
            let (id, content, created_at_ms, metadata_raw, distance) = match row {
                Ok(row) => row,
                Err(_) => continue,
            };
            let score = distance_to_score(distance);
            let metadata_value =
                serde_json::from_str::<Value>(&metadata_raw).unwrap_or_else(|_| json!({}));
            let metadata = match metadata_value {
                Value::Object(_) => metadata_value,
                _ => json!({}),
            };
            scored.push(MemoryCandidate {
                id,
                created_at_ms,
                content,
                score,
                metadata,
            });
        }

        let penalized = apply_supersedes_penalty(&mut scored);
        if penalized > 0 {
            scored.sort_by(|a, b| {
                b.score
                    .total_cmp(&a.score)
                    .then_with(|| b.created_at_ms.cmp(&a.created_at_ms))
                    .then_with(|| a.id.cmp(&b.id))
            });
        }
        scored.truncate(top_k.max(1));
        Ok(scored)
    }

    pub fn recall(&self, query_embedding: &[f32], top_k: usize) -> Result<Vec<MemoryItem>> {
        Ok(self
            .recall_candidates(query_embedding, top_k)?
            .into_iter()
            .map(|item| MemoryItem {
                content: item.content,
                score: item.score,
                metadata: item.metadata,
            })
            .collect())
    }

    pub fn delete(&self, memory_id: &str) -> Result<bool> {
        let _guard = self.lock.lock();
        let _file_lock = self.lock_exclusive()?;
        let (mut conn, _) = self.open_connection(None)?;
        let rowid: Option<i64> = conn
            .query_row(
                "SELECT rowid FROM memories WHERE id = ?1",
                params![memory_id],
                |row| row.get(0),
            )
            .optional()
            .context("lookup memory rowid")?;
        let Some(rowid) = rowid else {
            return Ok(false);
        };
        let tx = conn
            .transaction()
            .context("start memory delete transaction")?;
        tx.execute("DELETE FROM memories WHERE id = ?1", params![memory_id])
            .context("delete memory record")?;
        tx.execute("DELETE FROM memory_vec WHERE rowid = ?1", params![rowid])
            .context("delete memory vector")?;
        tx.commit().context("commit memory delete")?;
        Ok(true)
    }

    pub fn compact_superseded(&self, dry_run: bool) -> Result<MemoryCompactSummary> {
        let _guard = self.lock.lock();
        let _file_lock = self.lock_exclusive()?;
        let (mut conn, _) = self.open_connection(None)?;
        let mut total = 0usize;
        let mut superseded = 0usize;
        let mut to_delete: Vec<i64> = Vec::new();
        {
            let mut stmt = conn
                .prepare("SELECT rowid, metadata FROM memories")
                .context("prepare memory scan")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?;
            for row in rows {
                let (rowid, metadata_raw) = match row {
                    Ok(row) => row,
                    Err(_) => continue,
                };
                total += 1;
                let metadata_value =
                    serde_json::from_str::<Value>(&metadata_raw).unwrap_or_else(|_| json!({}));
                let metadata = match metadata_value {
                    Value::Object(_) => metadata_value,
                    _ => json!({}),
                };
                if metadata_is_superseded(&metadata) {
                    superseded += 1;
                    to_delete.push(rowid);
                }
            }
        }

        let mut deleted = 0usize;
        if !dry_run && !to_delete.is_empty() {
            let tx = conn
                .transaction()
                .context("start memory compaction transaction")?;
            for chunk in to_delete.chunks(MEMORY_COMPACT_CHUNK) {
                let placeholders = std::iter::repeat("?")
                    .take(chunk.len())
                    .collect::<Vec<_>>()
                    .join(", ");
                let delete_memories =
                    format!("DELETE FROM memories WHERE rowid IN ({placeholders})");
                let delete_vec = format!("DELETE FROM memory_vec WHERE rowid IN ({placeholders})");
                deleted += tx
                    .execute(&delete_memories, params_from_iter(chunk.iter()))
                    .context("delete superseded memories")? as usize;
                tx.execute(&delete_vec, params_from_iter(chunk.iter()))
                    .context("delete superseded memory vectors")?;
            }
            tx.execute(
                "DELETE FROM memory_vec WHERE rowid NOT IN (SELECT rowid FROM memories)",
                [],
            )
            .context("cleanup memory vector rows")?;
            tx.commit().context("commit memory compaction")?;
            let _ = conn.execute_batch("PRAGMA optimize;");
        }

        Ok(MemoryCompactSummary {
            total,
            superseded,
            deleted,
            dry_run,
        })
    }

    fn lock_shared(&self) -> Result<FileLock> {
        FileLock::acquire(&self.lock_path, true)
    }

    fn lock_exclusive(&self) -> Result<FileLock> {
        FileLock::acquire(&self.lock_path, false)
    }

    fn update_superseded_metadata(
        &self,
        conn: &mut Connection,
        superseded_ids: &[String],
        superseded_by: &str,
        superseded_at_ms: i64,
    ) -> Result<usize> {
        if superseded_ids.is_empty() {
            return Ok(0);
        }
        let mut updated = 0usize;
        let mut select = conn
            .prepare("SELECT metadata FROM memories WHERE id = ?1")
            .context("prepare superseded metadata fetch")?;
        let mut update = conn
            .prepare("UPDATE memories SET metadata = ?1 WHERE id = ?2")
            .context("prepare superseded metadata update")?;
        for superseded_id in superseded_ids {
            if superseded_id == superseded_by {
                continue;
            }
            let raw: Option<String> = select
                .query_row(params![superseded_id], |row| row.get(0))
                .optional()
                .context("fetch superseded metadata")?;
            let Some(raw) = raw else { continue };
            let mut metadata_value =
                serde_json::from_str::<Value>(&raw).unwrap_or_else(|_| json!({}));
            if !matches!(metadata_value, Value::Object(_)) {
                metadata_value = json!({});
            }
            mark_superseded_metadata(&mut metadata_value, superseded_by, superseded_at_ms);
            let metadata_json =
                serde_json::to_string(&metadata_value).context("serialize metadata")?;
            update.execute(params![metadata_json, superseded_id])?;
            updated += 1;
        }
        Ok(updated)
    }

    fn enforce_guardrails(&self, conn: &mut Connection) -> Result<()> {
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM memories", [], |row| row.get(0))
            .unwrap_or(0);
        if count >= MEMORY_WARN_ROWS && !MEMORY_WARNED.swap(true, Ordering::Relaxed) {
            warn!(
                target: "docdexd",
                count,
                "memory.db exceeds {MEMORY_WARN_ROWS} rows; pruning/compaction guardrail enabled"
            );
        }
        if count > MEMORY_WARN_ROWS {
            let target_rows = MEMORY_PRUNE_TARGET_ROWS.min(MEMORY_WARN_ROWS).max(1);
            let to_delete = count.saturating_sub(target_rows).max(1);
            let tx = conn
                .transaction()
                .context("start memory prune transaction")?;
            tx.execute(
                "DELETE FROM memories
                 WHERE rowid IN (
                    SELECT rowid FROM memories
                    ORDER BY created_at ASC, rowid ASC
                    LIMIT ?1
                 )",
                params![to_delete],
            )
            .context("prune memory rows")?;
            tx.execute(
                "DELETE FROM memory_vec WHERE rowid NOT IN (SELECT rowid FROM memories)",
                [],
            )
            .context("prune memory vector rows")?;
            tx.commit().context("commit memory prune")?;
            let _ = conn.execute_batch("PRAGMA optimize;");
            warn!(
                target: "docdexd",
                count,
                pruned = to_delete,
                remaining = target_rows,
                "memory.db pruned to enforce guardrail"
            );
        }
        Ok(())
    }
}

#[cfg(not(target_env = "musl"))]
fn ensure_vec_extension_loaded() -> Result<()> {
    SQLITE_VEC_INIT.call_once(|| unsafe {
        rusqlite::ffi::sqlite3_auto_extension(Some(std::mem::transmute(
            sqlite_vec::sqlite3_vec_init as *const (),
        )));
    });
    Ok(())
}

#[cfg(target_env = "musl")]
fn ensure_vec_extension_loaded() -> Result<()> {
    anyhow::bail!("sqlite-vec is not available on musl builds; memory vector search is disabled");
}

fn ensure_schema(conn: &Connection, embedding_dim: Option<usize>) -> Result<Option<usize>> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
        PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS memories(
            id TEXT PRIMARY KEY,
            content TEXT NOT NULL,
            embedding BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            metadata TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS memory_meta(
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );",
    )
    .context("ensure memory schema")?;

    ensure_schema_version(conn)?;

    let stored_dim = load_embedding_dim(conn)?;
    if let (Some(stored), Some(requested)) = (stored_dim, embedding_dim) {
        if stored != requested {
            return Err(anyhow::anyhow!(
                "embedding dimension mismatch: stored {stored}, requested {requested}"
            ));
        }
    }

    let inferred = if stored_dim.is_some() {
        stored_dim
    } else if embedding_dim.is_some() {
        embedding_dim
    } else {
        infer_embedding_dim(conn)?
    };

    if let Some(dim) = inferred {
        ensure_vec_table(conn, dim)?;
        if stored_dim.is_none() {
            conn.execute(
                "INSERT OR REPLACE INTO memory_meta (key, value) VALUES (?1, ?2)",
                params![MEMORY_META_EMBED_DIM, dim.to_string()],
            )
            .context("store embedding dimension")?;
        }
        backfill_vec_table(conn, dim)?;
    }

    Ok(inferred)
}

fn ensure_schema_version(conn: &Connection) -> Result<()> {
    let stored = load_schema_version(conn)?;
    match stored {
        None | Some(0) => {
            store_schema_version(conn, MEMORY_SCHEMA_VERSION)?;
        }
        Some(version) if version == MEMORY_SCHEMA_VERSION => {}
        Some(version) if version > MEMORY_SCHEMA_VERSION => {
            return Err(anyhow::anyhow!(
                "memory schema version {version} is newer than supported {MEMORY_SCHEMA_VERSION}"
            ));
        }
        Some(version) => {
            migrate_schema(conn, version, MEMORY_SCHEMA_VERSION)?;
            store_schema_version(conn, MEMORY_SCHEMA_VERSION)?;
        }
    }
    Ok(())
}

fn load_schema_version(conn: &Connection) -> Result<Option<u32>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM memory_meta WHERE key = ?1",
            params![MEMORY_META_SCHEMA_VERSION],
            |row| row.get(0),
        )
        .optional()
        .context("read schema version")?;
    match raw {
        None => Ok(None),
        Some(value) => value
            .trim()
            .parse::<u32>()
            .map(Some)
            .context("parse schema version"),
    }
}

fn store_schema_version(conn: &Connection, version: u32) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO memory_meta (key, value) VALUES (?1, ?2)",
        params![MEMORY_META_SCHEMA_VERSION, version.to_string()],
    )
    .context("store schema version")?;
    Ok(())
}

fn migrate_schema(conn: &Connection, from: u32, to: u32) -> Result<()> {
    let mut current = from;
    while current < to {
        let next = current + 1;
        match next {
            1 => {
                migrate_to_v1(conn)?;
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "unsupported memory schema migration {current}->{next}"
                ));
            }
        }
        current = next;
    }
    Ok(())
}

fn migrate_to_v1(conn: &Connection) -> Result<()> {
    let stored_dim = load_embedding_dim(conn)?;
    let inferred = if stored_dim.is_some() {
        stored_dim
    } else {
        infer_embedding_dim(conn)?
    };
    if let Some(dim) = inferred {
        ensure_vec_table(conn, dim)?;
        backfill_vec_table(conn, dim)?;
        if stored_dim.is_none() {
            conn.execute(
                "INSERT OR REPLACE INTO memory_meta (key, value) VALUES (?1, ?2)",
                params![MEMORY_META_EMBED_DIM, dim.to_string()],
            )
            .context("store embedding dimension")?;
        }
    }
    Ok(())
}

fn load_embedding_dim(conn: &Connection) -> Result<Option<usize>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM memory_meta WHERE key = ?1",
            params![MEMORY_META_EMBED_DIM],
            |row| row.get(0),
        )
        .optional()
        .context("read embedding dimension")?;
    match raw {
        None => Ok(None),
        Some(value) => value
            .trim()
            .parse::<usize>()
            .map(Some)
            .context("parse embedding dimension"),
    }
}

fn infer_embedding_dim(conn: &Connection) -> Result<Option<usize>> {
    let maybe_blob: Option<Vec<u8>> = conn
        .query_row("SELECT embedding FROM memories LIMIT 1", [], |row| {
            row.get(0)
        })
        .optional()
        .context("inspect existing embeddings")?;
    let Some(blob) = maybe_blob else {
        return Ok(None);
    };
    Ok(decode_embedding(&blob).map(|embedding| embedding.len()))
}

fn ensure_vec_table(conn: &Connection, embedding_dim: usize) -> Result<()> {
    let statement = format!(
        "CREATE VIRTUAL TABLE IF NOT EXISTS memory_vec USING vec0(embedding float[{embedding_dim}])"
    );
    conn.execute_batch(&statement)
        .context("ensure memory vector table")?;
    Ok(())
}

fn backfill_vec_table(conn: &Connection, embedding_dim: usize) -> Result<()> {
    let mem_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM memories", [], |row| row.get(0))
        .unwrap_or(0);
    if mem_count == 0 {
        return Ok(());
    }
    let vec_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM memory_vec", [], |row| row.get(0))
        .unwrap_or(0);
    if vec_count >= mem_count {
        return Ok(());
    }

    let mut stmt = conn
        .prepare(
            "SELECT rowid, embedding FROM memories
             WHERE rowid NOT IN (SELECT rowid FROM memory_vec)",
        )
        .context("prepare memory vec backfill")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    for row in rows {
        let (rowid, blob) = match row {
            Ok(row) => row,
            Err(_) => continue,
        };
        let Some(embedding) = decode_embedding(&blob) else {
            continue;
        };
        if embedding.len() != embedding_dim {
            continue;
        }
        let embedding_json = embedding_to_json(&embedding).context("serialize embedding")?;
        conn.execute(
            "INSERT OR IGNORE INTO memory_vec (rowid, embedding) VALUES (?1, ?2)",
            params![rowid, embedding_json],
        )
        .context("backfill memory vector")?;
    }
    Ok(())
}

fn embedding_to_json(embedding: &[f32]) -> Result<String> {
    serde_json::to_string(embedding).context("serialize embedding")
}

fn distance_to_score(distance: f64) -> f32 {
    let score = 1.0 / (1.0 + distance.max(0.0));
    score as f32
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

fn encode_embedding(embedding: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(embedding.len().saturating_mul(4));
    for value in embedding {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out
}

fn decode_embedding(blob: &[u8]) -> Option<Vec<f32>> {
    if blob.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(blob.len() / 4);
    for chunk in blob.chunks_exact(4) {
        let bytes: [u8; 4] = chunk.try_into().ok()?;
        out.push(f32::from_le_bytes(bytes));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn open_connection_enables_wal_and_busy_timeout() -> Result<()> {
        let dir = TempDir::new()?;
        let store = MemoryStore::new(dir.path());

        let (conn, _) = store.open_connection(None)?;
        let journal_mode: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        let busy_timeout_ms: i64 = conn.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;

        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
        assert!(busy_timeout_ms >= (crate::sqlite::SQLITE_BUSY_TIMEOUT_SECS as i64) * 1000);

        Ok(())
    }

    #[test]
    fn delete_removes_memory_and_vector_once() -> Result<()> {
        let dir = TempDir::new()?;
        let store = MemoryStore::new(dir.path());
        let (id, _) = store.store(
            "remember the repo rule",
            &[0.1, 0.2, 0.3, 0.4],
            json!({}),
            1,
        )?;

        assert_eq!(store.recall(&[0.1, 0.2, 0.3, 0.4], 5)?.len(), 1);
        assert!(store.delete(&id.to_string())?);
        assert!(store.recall(&[0.1, 0.2, 0.3, 0.4], 5)?.is_empty());
        assert!(!store.delete(&id.to_string())?);

        Ok(())
    }
}
