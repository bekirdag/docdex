use crate::memory::ops::{cosine_similarity, MemoryCandidate, MemoryItem};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
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

    pub fn store(
        &self,
        content: &str,
        embedding: &[f32],
        metadata: Value,
        created_at_ms: i64,
    ) -> Result<(Uuid, i64)> {
        let _guard = self.lock.lock();
        let id = Uuid::new_v4();
        let record = MemoryRecord {
            id: id.to_string(),
            content: content.to_string(),
            embedding: embedding.to_vec(),
            created_at: created_at_ms,
            metadata,
        };
        let line = serde_json::to_string(&record).context("serialize memory record")?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("open {}", self.path.display()))?;
        file.write_all(line.as_bytes())
            .context("write memory record")?;
        file.write_all(b"\n").context("write newline")?;
        file.flush().ok();
        Ok((id, created_at_ms))
    }

    pub fn recall_candidates(
        &self,
        query_embedding: &[f32],
        top_k: usize,
    ) -> Result<Vec<MemoryCandidate>> {
        let _guard = self.lock.lock();
        let file = match OpenOptions::new().read(true).open(&self.path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err).with_context(|| format!("open {}", self.path.display())),
        };
        let reader = BufReader::new(file);
        let mut scored: Vec<MemoryCandidate> = Vec::new();

        for line in reader.lines() {
            let line = match line {
                Ok(line) => line,
                Err(_) => continue,
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let parsed: MemoryRecord = match serde_json::from_str(trimmed) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let Some(score) = cosine_similarity(query_embedding, &parsed.embedding) else {
                continue;
            };
            let metadata = match parsed.metadata {
                Value::Object(_) => parsed.metadata,
                _ => json!({}),
            };
            scored.push(MemoryCandidate {
                id: parsed.id,
                created_at_ms: parsed.created_at,
                content: parsed.content,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MemoryRecord {
    id: String,
    content: String,
    embedding: Vec<f32>,
    created_at: i64,
    #[serde(default)]
    metadata: Value,
}
