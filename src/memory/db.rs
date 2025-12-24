use crate::memory::ops::{cosine_similarity, MemoryCandidate, MemoryItem};
use anyhow::{Context, Result};
use fs4::FileExt;
use rusqlite::{params, Connection, OpenFlags};
use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::warn;
use uuid::Uuid;

const MEMORY_WARN_ROWS: i64 = 50_000;
static MEMORY_WARNED: AtomicBool = AtomicBool::new(false);

#[derive(Clone)]
pub struct MemoryStore {
    path: PathBuf,
    lock: Arc<parking_lot::Mutex<()>>,
    lock_path: PathBuf,
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

    fn open_connection(&self) -> Result<Connection> {
        let conn = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
        )
        .with_context(|| format!("open {}", self.path.display()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS memories(
                id TEXT PRIMARY KEY,
                content TEXT NOT NULL,
                embedding BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                metadata TEXT NOT NULL
            )",
        )
        .context("ensure memory schema")?;
        Ok(conn)
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
        let metadata_json = serde_json::to_string(&metadata).context("serialize metadata")?;
        let conn = self.open_connection()?;
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
        self.warn_if_large(&conn)?;
        Ok((id, created_at_ms))
    }

    pub fn recall_candidates(
        &self,
        query_embedding: &[f32],
        top_k: usize,
    ) -> Result<Vec<MemoryCandidate>> {
        let _guard = self.lock.lock();
        let _file_lock = self.lock_shared()?;
        let conn = self.open_connection()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, content, embedding, created_at, metadata
                 FROM memories",
            )
            .context("prepare memory recall")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        let mut scored: Vec<MemoryCandidate> = Vec::new();

        for row in rows {
            let (id, content, embedding_blob, created_at_ms, metadata_raw) = match row {
                Ok(row) => row,
                Err(_) => continue,
            };
            let Some(embedding) = decode_embedding(&embedding_blob) else {
                continue;
            };
            let Some(score) = cosine_similarity(query_embedding, &embedding) else {
                continue;
            };
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

        scored.sort_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then_with(|| b.created_at_ms.cmp(&a.created_at_ms))
                .then_with(|| a.id.cmp(&b.id))
        });
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

    fn lock_shared(&self) -> Result<FileLock> {
        FileLock::acquire(&self.lock_path, true)
    }

    fn lock_exclusive(&self) -> Result<FileLock> {
        FileLock::acquire(&self.lock_path, false)
    }

    fn warn_if_large(&self, conn: &Connection) -> Result<()> {
        if MEMORY_WARNED.load(Ordering::Relaxed) {
            return Ok(());
        }
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM memories", [], |row| row.get(0))
            .unwrap_or(0);
        if count >= MEMORY_WARN_ROWS {
            if !MEMORY_WARNED.swap(true, Ordering::Relaxed) {
                warn!(
                    target: "docdexd",
                    count,
                    "memory.db exceeds {MEMORY_WARN_ROWS} rows; consider pruning or compaction"
                );
            }
        }
        Ok(())
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
