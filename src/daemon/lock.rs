use anyhow::{anyhow, Context, Result};
use fs4::FileExt;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonLockMetadata {
    pub pid: u32,
    pub port: u16,
    pub started_at_ms: u128,
}

pub struct DaemonLock {
    _file: File,
    path: PathBuf,
    pub metadata: DaemonLockMetadata,
}

impl DaemonLock {
    pub fn acquire(port: u16) -> Result<Self> {
        let path = default_lock_path()?;
        acquire_lock_at_path(&path, port)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub fn default_lock_path() -> Result<PathBuf> {
    if let Ok(value) = env::var("DOCDEX_DAEMON_LOCK_PATH") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    let state_dir = crate::state_paths::default_state_base_dir()?;
    let Some(root) = state_dir.parent() else {
        return Err(anyhow!(
            "unable to resolve daemon lock path from {}",
            state_dir.display()
        ));
    };
    Ok(root.join("daemon.lock"))
}

pub fn acquire_lock_at_path(path: &Path, port: u16) -> Result<DaemonLock> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create daemon lock dir {}", parent.display()))?;
    }
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("open daemon lock {}", path.display()))?;
    file.try_lock_exclusive()
        .with_context(|| "daemon lock already held")?;
    let metadata = DaemonLockMetadata {
        pid: std::process::id(),
        port,
        started_at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    };
    write_metadata(&file, &metadata)?;
    Ok(DaemonLock {
        _file: file,
        path: path.to_path_buf(),
        metadata,
    })
}

pub fn read_metadata(path: &Path) -> Result<Option<DaemonLockMetadata>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    read_metadata_from_file(&mut file)
        .map(Some)
        .or_else(|_| Ok(None))
}

fn read_metadata_from_file(file: &mut File) -> Result<DaemonLockMetadata> {
    file.seek(SeekFrom::Start(0))?;
    let mut raw = String::new();
    let mut reader = std::io::BufReader::new(file);
    reader
        .read_to_string(&mut raw)
        .context("read daemon lock metadata")?;
    serde_json::from_str(&raw).context("parse daemon lock metadata")
}

fn write_metadata(file: &File, metadata: &DaemonLockMetadata) -> Result<()> {
    file.set_len(0)?;
    file.sync_all()?;
    let mut handle = file;
    handle.seek(SeekFrom::Start(0))?;
    let payload = serde_json::to_string(metadata).context("serialize daemon lock metadata")?;
    handle
        .write_all(payload.as_bytes())
        .context("write daemon lock metadata")?;
    file.sync_all().context("flush daemon lock metadata")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn lock_metadata_roundtrip() -> Result<()> {
        let dir = TempDir::new()?;
        let path = dir.path().join("daemon.lock");
        let lock = acquire_lock_at_path(&path, 3210)?;
        let expected_pid = lock.metadata.pid;
        drop(lock);
        let snapshot = read_metadata(&path)?.expect("metadata present");
        assert_eq!(snapshot.pid, expected_pid);
        assert_eq!(snapshot.port, 3210);
        Ok(())
    }
}
