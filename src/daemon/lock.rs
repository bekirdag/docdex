use anyhow::{anyhow, Context, Result};
use fs4::FileExt;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

pub enum DaemonLockOutcome {
    Acquired(DaemonLock),
    AlreadyRunning(DaemonLockMetadata),
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

pub fn acquire_or_reuse(port: u16) -> Result<DaemonLockOutcome> {
    let path = default_lock_path()?;
    acquire_or_reuse_at_path(&path, port)
}

pub fn default_lock_path() -> Result<PathBuf> {
    if let Ok(value) = env::var("DOCDEX_DAEMON_LOCK_PATH") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    if let Ok(state_dir) = crate::state_paths::default_state_base_dir() {
        if let Some(root) = state_dir.parent() {
            return Ok(root.join("locks").join("daemon.lock"));
        }
    }
    Ok(std::env::temp_dir()
        .join("docdex")
        .join("locks")
        .join("daemon.lock"))
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

pub fn read_running_metadata() -> Result<Option<DaemonLockMetadata>> {
    let path = default_lock_path()?;
    read_running_metadata_at_path(&path)
}

pub fn read_running_metadata_at_path(path: &Path) -> Result<Option<DaemonLockMetadata>> {
    let metadata = read_metadata(path)?;
    if let Some(metadata) = metadata {
        if probe_health(metadata.port) {
            return Ok(Some(metadata));
        }
        if lock_held(path)? {
            return Ok(Some(metadata));
        }
    }
    Ok(None)
}

pub fn wait_for_running_metadata(timeout: Duration) -> Result<Option<DaemonLockMetadata>> {
    let path = default_lock_path()?;
    wait_for_running_metadata_at_path(&path, timeout)
}

pub fn wait_for_running_metadata_at_path(
    path: &Path,
    timeout: Duration,
) -> Result<Option<DaemonLockMetadata>> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(metadata) = read_running_metadata_at_path(path)? {
            return Ok(Some(metadata));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(None)
}

fn read_metadata_strict(path: &Path) -> Result<Option<DaemonLockMetadata>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    read_metadata_from_file(&mut file).map(Some)
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

fn acquire_or_reuse_at_path(path: &Path, port: u16) -> Result<DaemonLockOutcome> {
    let metadata = match read_metadata_strict(path) {
        Ok(value) => value,
        Err(_) => {
            if lock_held(path)? {
                return Err(anyhow!(
                    "daemon lock held but metadata is unreadable; remove {} if the daemon is not running",
                    path.display()
                ));
            }
            None
        }
    };
    if let Some(metadata) = metadata {
        if probe_health(metadata.port) {
            return Ok(DaemonLockOutcome::AlreadyRunning(metadata));
        }
        if lock_held(path)? {
            return Ok(DaemonLockOutcome::AlreadyRunning(metadata));
        }
    }
    let lock = acquire_lock_at_path(path, port)?;
    Ok(DaemonLockOutcome::Acquired(lock))
}

fn lock_held(path: &Path) -> Result<bool> {
    let file = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err.into()),
    };
    if file.try_lock_exclusive().is_ok() {
        let _ = file.unlock();
        return Ok(false);
    }
    Ok(true)
}

fn probe_health(port: u16) -> bool {
    if port == 0 {
        return false;
    }
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(300)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(300)));
    let request = format!(
        "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut buf = [0u8; 32];
    let Ok(read) = stream.read(&mut buf) else {
        return false;
    };
    if read == 0 {
        return false;
    }
    let head = std::str::from_utf8(&buf[..read]).unwrap_or("");
    head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200")
}

#[cfg(test)]
mod tests {
    use super::*;
    use once_cell::sync::Lazy;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Mutex, MutexGuard};
    use std::thread;
    use tempfile::TempDir;

    static ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    struct EnvGuard {
        prev: Vec<(&'static str, Option<String>)>,
        _lock: MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn new(keys: &[&'static str]) -> Self {
            let lock = ENV_LOCK.lock().expect("env lock");
            let prev = keys
                .iter()
                .map(|key| (*key, std::env::var(*key).ok()))
                .collect();
            Self { prev, _lock: lock }
        }

        fn set(&self, key: &'static str, value: &str) {
            std::env::set_var(key, value);
        }

        fn clear(&self, key: &'static str) {
            std::env::remove_var(key);
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, prev) in &self.prev {
                if let Some(value) = prev {
                    std::env::set_var(*key, value);
                } else {
                    std::env::remove_var(*key);
                }
            }
        }
    }

    fn unused_port() -> Option<u16> {
        match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => Some(listener.local_addr().expect("local addr").port()),
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => None,
            Err(err) => panic!("bind ephemeral port: {err}"),
        }
    }

    fn spawn_health_server() -> Option<(u16, thread::JoinHandle<()>)> {
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return None,
            Err(err) => panic!("bind health listener: {err}"),
        };
        let port = listener.local_addr().expect("listener addr").port();
        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 64];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length:2\r\nConnection: close\r\n\r\nOK",
                );
            }
        });
        Some((port, handle))
    }

    #[test]
    fn default_lock_path_prefers_env_override() -> Result<()> {
        let dir = TempDir::new()?;
        let guard = EnvGuard::new(&[
            "DOCDEX_DAEMON_LOCK_PATH",
            "HOME",
            "USERPROFILE",
            "HOMEDRIVE",
            "HOMEPATH",
        ]);
        let custom = dir.path().join("custom.lock");
        guard.set("DOCDEX_DAEMON_LOCK_PATH", custom.to_string_lossy().as_ref());
        let resolved = default_lock_path()?;
        assert_eq!(resolved, custom);
        Ok(())
    }

    #[test]
    fn default_lock_path_uses_home_locks_dir() -> Result<()> {
        let dir = TempDir::new()?;
        let guard = EnvGuard::new(&[
            "DOCDEX_DAEMON_LOCK_PATH",
            "HOME",
            "USERPROFILE",
            "HOMEDRIVE",
            "HOMEPATH",
        ]);
        guard.clear("DOCDEX_DAEMON_LOCK_PATH");
        guard.set("HOME", dir.path().to_string_lossy().as_ref());
        guard.clear("USERPROFILE");
        guard.clear("HOMEDRIVE");
        guard.clear("HOMEPATH");
        let resolved = default_lock_path()?;
        let expected = dir.path().join(".docdex").join("locks").join("daemon.lock");
        assert_eq!(resolved, expected);
        Ok(())
    }

    #[test]
    fn default_lock_path_falls_back_to_temp_dir() -> Result<()> {
        let guard = EnvGuard::new(&[
            "DOCDEX_DAEMON_LOCK_PATH",
            "HOME",
            "USERPROFILE",
            "HOMEDRIVE",
            "HOMEPATH",
        ]);
        guard.clear("DOCDEX_DAEMON_LOCK_PATH");
        guard.clear("HOME");
        guard.clear("USERPROFILE");
        guard.clear("HOMEDRIVE");
        guard.clear("HOMEPATH");
        let resolved = default_lock_path()?;
        let expected = std::env::temp_dir()
            .join("docdex")
            .join("locks")
            .join("daemon.lock");
        assert_eq!(resolved, expected);
        Ok(())
    }

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

    #[test]
    fn acquire_or_reuse_returns_running_when_healthy() -> Result<()> {
        let dir = TempDir::new()?;
        let path = dir.path().join("daemon.lock");
        let Some((port, handle)) = spawn_health_server() else {
            eprintln!("skipping health probe test: TCP bind not permitted");
            return Ok(());
        };
        let lock = acquire_lock_at_path(&path, port)?;
        drop(lock);
        let outcome = acquire_or_reuse_at_path(&path, 9999)?;
        match outcome {
            DaemonLockOutcome::AlreadyRunning(metadata) => {
                assert_eq!(metadata.port, port);
            }
            DaemonLockOutcome::Acquired(_) => {
                panic!("expected existing daemon detection");
            }
        }
        let _ = handle.join();
        Ok(())
    }

    #[test]
    fn acquire_or_reuse_replaces_stale_lock() -> Result<()> {
        let dir = TempDir::new()?;
        let path = dir.path().join("daemon.lock");
        let Some(stale_port) = unused_port() else {
            eprintln!("skipping stale lock test: TCP bind not permitted");
            return Ok(());
        };
        let stale_lock = acquire_lock_at_path(&path, stale_port)?;
        drop(stale_lock);
        let Some(new_port) = unused_port() else {
            eprintln!("skipping stale lock test: TCP bind not permitted");
            return Ok(());
        };
        let outcome = acquire_or_reuse_at_path(&path, new_port)?;
        let lock = match outcome {
            DaemonLockOutcome::Acquired(lock) => lock,
            DaemonLockOutcome::AlreadyRunning(_) => {
                panic!("expected stale lock replacement");
            }
        };
        assert_eq!(lock.metadata.port, new_port);
        let snapshot = read_metadata(&path)?.expect("metadata present");
        assert_eq!(snapshot.port, new_port);
        Ok(())
    }
}
