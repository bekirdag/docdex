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

#[derive(Debug, Clone)]
pub struct MemoryItem {
    pub content: String,
    pub score: f32,
    pub metadata: Value,
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

impl MemoryStore {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            path: state_dir.join("memory.jsonl"),
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

    pub fn recall(&self, query_embedding: &[f32], top_k: usize) -> Result<Vec<MemoryItem>> {
        let _guard = self.lock.lock();
        let file = match OpenOptions::new().read(true).open(&self.path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err).with_context(|| format!("open {}", self.path.display())),
        };
        let reader = BufReader::new(file);
        let mut scored: Vec<MemoryItem> = Vec::new();

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
            scored.push(MemoryItem {
                content: parsed.content,
                score,
                metadata,
            });
        }

        scored.sort_by(|a, b| b.score.total_cmp(&a.score));
        scored.truncate(top_k.max(1));
        Ok(scored)
    }
}

pub fn inject_embedding_metadata(
    user: Option<Value>,
    embedding_provider: &str,
    embedding_model: &str,
) -> Value {
    let mut value = match user {
        Some(Value::Object(map)) => Value::Object(map),
        Some(_) => json!({}),
        None => json!({}),
    };
    let obj = value
        .as_object_mut()
        .expect("json!({}) always produces object");
    obj.insert(
        "embeddingProvider".to_string(),
        Value::String(embedding_provider.to_string()),
    );
    obj.insert(
        "embeddingModel".to_string(),
        Value::String(embedding_model.to_string()),
    );
    value
}

fn cosine_similarity(a: &[f32], b: &[f32]) -> Option<f32> {
    if a.len() != b.len() || a.is_empty() {
        return None;
    }
    let mut dot = 0.0f64;
    let mut norm_a = 0.0f64;
    let mut norm_b = 0.0f64;
    for (a_i, b_i) in a.iter().zip(b.iter()) {
        dot += (*a_i as f64) * (*b_i as f64);
        norm_a += (*a_i as f64) * (*a_i as f64);
        norm_b += (*b_i as f64) * (*b_i as f64);
    }
    if norm_a == 0.0 || norm_b == 0.0 {
        return None;
    }
    Some((dot / (norm_a.sqrt() * norm_b.sqrt())) as f32)
}

