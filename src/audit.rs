use anyhow::Result;
use chrono::Utc;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone)]
pub struct AuditLogger {
    inner: Arc<std::sync::Mutex<AuditState>>,
}

struct AuditState {
    path: PathBuf,
    max_bytes: u64,
    max_files: usize,
    prev_hash: Option<String>,
    writer: BufWriter<File>,
}

#[derive(Serialize)]
struct AuditRecord<'a> {
    ts: String,
    event: &'a str,
    outcome: &'a str,
    request_id: Option<&'a str>,
    path: Option<&'a str>,
    method: Option<&'a str>,
    status: Option<u16>,
    client_ip: Option<&'a str>,
    detail: Option<&'a str>,
    prev_hash: Option<&'a str>,
    hash: String,
}

impl AuditLogger {
    pub fn new(path: PathBuf, max_bytes: u64, max_files: usize) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let (writer, prev_hash) = open_with_prev_hash(&path)?;
        Ok(Self {
            inner: Arc::new(std::sync::Mutex::new(AuditState {
                path,
                max_bytes,
                max_files: max_files.max(1),
                prev_hash,
                writer,
            })),
        })
    }

    pub fn log(
        &self,
        event: &str,
        outcome: &str,
        request_id: Option<&str>,
        path: Option<&str>,
        method: Option<&str>,
        status: Option<u16>,
        client_ip: Option<&str>,
        detail: Option<&str>,
    ) {
        if let Err(err) = self.write_record(
            event, outcome, request_id, path, method, status, client_ip, detail,
        ) {
            tracing::warn!(target: "docdexd", error = ?err, "failed to write audit log");
        }
    }

    fn write_record(
        &self,
        event: &str,
        outcome: &str,
        request_id: Option<&str>,
        path: Option<&str>,
        method: Option<&str>,
        status: Option<u16>,
        client_ip: Option<&str>,
        detail: Option<&str>,
    ) -> Result<()> {
        let mut guard = self.inner.lock().unwrap();
        guard.rotate_if_needed()?;
        let prev_hash = guard.prev_hash.clone();
        let ts = Utc::now().to_rfc3339();
        let mut record = AuditRecord {
            ts,
            event,
            outcome,
            request_id,
            path,
            method,
            status,
            client_ip,
            detail,
            prev_hash: prev_hash.as_deref(),
            hash: String::new(),
        };
        let serialized = serde_json::to_vec(&record)?;
        let digest = Sha256::digest(&serialized);
        record.hash = hex::encode(digest);
        let line = serde_json::to_vec(&record)?;
        guard.writer.write_all(&line)?;
        guard.writer.write_all(b"\n")?;
        guard.writer.flush()?;
        guard.prev_hash = Some(record.hash.clone());
        Ok(())
    }
}

fn open_with_prev_hash(path: &Path) -> Result<(BufWriter<File>, Option<String>)> {
    let file = File::options()
        .create(true)
        .append(true)
        .read(true)
        .open(path)?;
    let prev_hash = last_hash(path)?;
    Ok((BufWriter::new(file), prev_hash))
}

fn last_hash(path: &Path) -> Result<Option<String>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return Ok(None),
    };
    let reader = BufReader::new(file);
    let mut last = None;
    for line in reader
        .lines()
        .filter_map(|l| l.ok())
        .filter(|l| !l.is_empty())
    {
        last = Some(line);
    }
    if let Some(line) = last {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&line) {
            if let Some(hash) = json.get("hash").and_then(|v| v.as_str()) {
                return Ok(Some(hash.to_string()));
            }
        }
    }
    Ok(None)
}

impl AuditState {
    fn rotate_if_needed(&mut self) -> Result<()> {
        let len = self.path.metadata().map(|m| m.len()).unwrap_or(0);
        if len < self.max_bytes {
            return Ok(());
        }
        self.writer.flush()?;
        self.rotate_files()?;
        let (writer, _) = open_with_prev_hash(&self.path)?;
        self.writer = writer;
        Ok(())
    }

    fn rotate_files(&self) -> Result<()> {
        for idx in (1..self.max_files).rev() {
            let old = self.rotated_name(idx);
            let new = self.rotated_name(idx + 1);
            if old.exists() {
                let _ = fs::remove_file(&new);
                fs::rename(&old, &new)?;
            }
        }
        let first = self.rotated_name(1);
        let _ = fs::remove_file(&first);
        fs::rename(&self.path, &first)?;
        Ok(())
    }

    fn rotated_name(&self, idx: usize) -> PathBuf {
        let mut name = self
            .path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| "audit.log".to_string());
        name.push('.');
        name.push_str(&idx.to_string());
        self.path
            .parent()
            .map(|p| p.join(&name))
            .unwrap_or_else(|| PathBuf::from(&name))
    }
}
