use crate::memory::ops::{cosine_similarity, MemoryCandidate, MemoryItem};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use rusqlite::{params, Connection, OpenFlags};
use uuid::Uuid;

#[derive(Clone)]
pub struct MemoryStore {
    path: PathBuf,
    lock: Arc<parking_lot::Mutex<()>>,
}

impl MemoryStore {
    pub fn new(state_dir: &Path) -> Self {
        let _ = crate::memory::ensure_repo_state_dir(state_dir);
        let path = crate::memory::memory_path(state_dir);
        Self {
            path,
            lock: Arc::new(parking_lot::Mutex::new(())),
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
        Ok((id, created_at_ms))
    }

    pub fn recall_candidates(
        &self,
        query_embedding: &[f32],
        top_k: usize,
    ) -> Result<Vec<MemoryCandidate>> {
        let _guard = self.lock.lock();
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
