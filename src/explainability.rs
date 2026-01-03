use crate::error::{AppError, ERR_INVALID_ARGUMENT};
use anyhow::{Context, Result};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_STRING_BYTES: usize = 2048;
const MIN_STRING_BYTES: usize = 32;
const MAX_ARRAY_ITEMS: usize = 200;
const MAX_OBJECT_KEYS: usize = 200;
const MAX_DEPTH: usize = 12;
const MAX_COMPLETION_ID_BYTES: usize = 128;
const MAX_SCHEMA_VERSION_BYTES: usize = 64;

const REQUIRED_TOP_LEVEL_KEYS: [&str; 2] = ["schemaVersion", "completionId"];

#[derive(Clone)]
pub struct ExplainabilityStore {
    base_dir: PathBuf,
    lock: Arc<parking_lot::Mutex<()>>,
}

#[derive(Debug, Clone)]
pub struct StoredExplainability {
    pub completion_id: String,
    pub record_bytes: usize,
}

impl ExplainabilityStore {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            base_dir: state_dir.join("explainability"),
            lock: Arc::new(parking_lot::Mutex::new(())),
        }
    }

    pub fn store(&self, record: Value) -> Result<StoredExplainability> {
        let _guard = self.lock.lock();
        let obj = record.as_object().ok_or_else(|| {
            AppError::new(ERR_INVALID_ARGUMENT, "record must be a JSON object")
        })?;
        let completion_id = required_string_field(obj, "completionId", MAX_COMPLETION_ID_BYTES)?;
        let _schema_version = required_string_field(obj, "schemaVersion", MAX_SCHEMA_VERSION_BYTES)?;
        let bounded = clamp_record(&record)?;
        let payload = serde_json::to_vec(&bounded).context("serialize explainability record")?;
        if payload.len() > MAX_RECORD_BYTES {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "explainability record exceeds max size after truncation",
            )
            .into());
        }

        let records_dir = self.base_dir.join("records");
        fs::create_dir_all(&records_dir).context("create explainability records dir")?;
        let path = record_path(&records_dir, &completion_id);
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, &payload).context("write explainability record temp file")?;
        if path.exists() {
            let _ = fs::remove_file(&path);
        }
        fs::rename(&tmp, &path).or_else(|err| {
            let _ = fs::remove_file(&tmp);
            Err(err)
        })?;
        Ok(StoredExplainability {
            completion_id,
            record_bytes: payload.len(),
        })
    }
}

fn required_string_field(
    obj: &Map<String, Value>,
    field: &'static str,
    max_bytes: usize,
) -> Result<String> {
    let raw = obj
        .get(field)
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            AppError::new(
                ERR_INVALID_ARGUMENT,
                format!("record.{field} must be a non-empty string"),
            )
        })?;
    if raw.trim().is_empty() {
        return Err(AppError::new(
            ERR_INVALID_ARGUMENT,
            format!("record.{field} must be a non-empty string"),
        )
        .into());
    }
    if raw.as_bytes().len() > max_bytes {
        return Err(AppError::new(
            ERR_INVALID_ARGUMENT,
            format!("record.{field} exceeds max length"),
        )
        .into());
    }
    Ok(raw.to_string())
}

fn record_path(records_dir: &Path, completion_id: &str) -> PathBuf {
    let digest = Sha256::digest(completion_id.as_bytes());
    let name = format!("{}.json", hex::encode(digest));
    records_dir.join(name)
}

fn clamp_record(record: &Value) -> Result<Value> {
    let mut limits = TruncationLimits::default();
    let mut result = truncate_value(record, &limits, 0, false).value;
    let mut size = serde_json::to_vec(&result)
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX);
    while size > MAX_RECORD_BYTES && limits.shrink() {
        result = truncate_value(record, &limits, 0, false).value;
        size = serde_json::to_vec(&result)
            .map(|bytes| bytes.len())
            .unwrap_or(usize::MAX);
    }
    if size > MAX_RECORD_BYTES {
        result = minimal_record(record);
    }
    Ok(result)
}

#[derive(Clone, Copy)]
struct TruncationLimits {
    max_string_bytes: usize,
    max_array_items: usize,
    max_object_keys: usize,
    max_depth: usize,
}

impl Default for TruncationLimits {
    fn default() -> Self {
        Self {
            max_string_bytes: MAX_STRING_BYTES,
            max_array_items: MAX_ARRAY_ITEMS,
            max_object_keys: MAX_OBJECT_KEYS,
            max_depth: MAX_DEPTH,
        }
    }
}

impl TruncationLimits {
    fn shrink(&mut self) -> bool {
        let mut changed = false;
        let new_string = (self.max_string_bytes / 2).max(MIN_STRING_BYTES);
        let new_array = (self.max_array_items / 2).max(1);
        let new_keys = (self.max_object_keys / 2).max(1);
        if new_string < self.max_string_bytes {
            self.max_string_bytes = new_string;
            changed = true;
        }
        if new_array < self.max_array_items {
            self.max_array_items = new_array;
            changed = true;
        }
        if new_keys < self.max_object_keys {
            self.max_object_keys = new_keys;
            changed = true;
        }
        changed
    }
}

struct TruncateOutcome {
    value: Value,
    truncated: bool,
}

fn truncate_value(
    value: &Value,
    limits: &TruncationLimits,
    depth: usize,
    protect_strings: bool,
) -> TruncateOutcome {
    if depth >= limits.max_depth {
        return TruncateOutcome {
            value: empty_for_type(value),
            truncated: true,
        };
    }
    match value {
        Value::String(raw) => {
            if protect_strings {
                return TruncateOutcome {
                    value: Value::String(raw.clone()),
                    truncated: false,
                };
            }
            let (trimmed, changed) = truncate_string(raw, limits.max_string_bytes);
            TruncateOutcome {
                value: Value::String(trimmed),
                truncated: changed,
            }
        }
        Value::Array(items) => {
            let mut truncated = items.len() > limits.max_array_items;
            let mut out = Vec::with_capacity(items.len().min(limits.max_array_items));
            for item in items.iter().take(limits.max_array_items) {
                let next = truncate_value(item, limits, depth + 1, false);
                truncated |= next.truncated;
                out.push(next.value);
            }
            TruncateOutcome {
                value: Value::Array(out),
                truncated,
            }
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut keep: Vec<String> = Vec::new();
            let mut keep_set: HashSet<String> = HashSet::new();
            if depth == 0 {
                for key in REQUIRED_TOP_LEVEL_KEYS {
                    if map.contains_key(key) {
                        keep.push(key.to_string());
                        keep_set.insert(key.to_string());
                    }
                }
            }
            let mut remaining = if limits.max_object_keys > keep.len() {
                limits.max_object_keys - keep.len()
            } else {
                0
            };
            for key in keys {
                if keep_set.contains(key) {
                    continue;
                }
                if remaining == 0 {
                    break;
                }
                keep.push(key.clone());
                keep_set.insert(key.clone());
                remaining -= 1;
            }
            let mut truncated = map.len() > keep.len();
            let mut out = Map::new();
            for key in keep {
                if let Some(val) = map.get(&key) {
                    let protect = depth == 0
                        && REQUIRED_TOP_LEVEL_KEYS
                            .iter()
                            .any(|protected| protected == &key);
                    let next = truncate_value(val, limits, depth + 1, protect);
                    truncated |= next.truncated;
                    out.insert(key, next.value);
                }
            }
            TruncateOutcome {
                value: Value::Object(out),
                truncated,
            }
        }
        _ => TruncateOutcome {
            value: value.clone(),
            truncated: false,
        },
    }
}

fn empty_for_type(value: &Value) -> Value {
    match value {
        Value::Object(_) => Value::Object(Map::new()),
        Value::Array(_) => Value::Array(Vec::new()),
        Value::String(_) => Value::String(String::new()),
        _ => value.clone(),
    }
}

fn truncate_string(value: &str, max_bytes: usize) -> (String, bool) {
    if value.as_bytes().len() <= max_bytes {
        return (value.to_string(), false);
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    (value[..end].to_string(), true)
}

fn minimal_record(record: &Value) -> Value {
    let mut out = Map::new();
    if let Value::Object(map) = record {
        for key in REQUIRED_TOP_LEVEL_KEYS {
            if let Some(value) = map.get(key) {
                if let Value::String(raw) = value {
                    let (trimmed, _) = truncate_string(raw, MIN_STRING_BYTES);
                    out.insert(key.to_string(), Value::String(trimmed));
                } else {
                    out.insert(key.to_string(), value.clone());
                }
            }
        }
    }
    Value::Object(out)
}
