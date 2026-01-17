use super::{normalize_base_url, resolve_base_url_with_lock, CliHttpClient};
use crate::setup::test_support::ENV_LOCK;
use parking_lot::ReentrantMutexGuard;
use reqwest::Method;
use tempfile::TempDir;

struct EnvGuard {
    prev: Vec<(&'static str, Option<String>)>,
    _lock: ReentrantMutexGuard<'static, ()>,
}

impl EnvGuard {
    fn set(vars: &[(&'static str, &str)]) -> Self {
        let lock = ENV_LOCK.lock();
        let mut prev = Vec::new();
        for (key, value) in vars {
            let old = std::env::var(key).ok();
            std::env::set_var(key, value);
            prev.push((*key, old));
        }
        Self { prev, _lock: lock }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, value) in &self.prev {
            if let Some(value) = value {
                std::env::set_var(key, value);
            } else {
                std::env::remove_var(key);
            }
        }
    }
}

#[test]
fn normalize_base_url_adds_scheme() {
    assert_eq!(
        normalize_base_url("127.0.0.1:28491"),
        "http://127.0.0.1:28491"
    );
    assert_eq!(
        normalize_base_url("http://localhost:28491"),
        "http://localhost:28491"
    );
}

#[test]
fn request_adds_auth_header_when_present() -> Result<(), Box<dyn std::error::Error>> {
    let _env = EnvGuard::set(&[
        ("DOCDEX_HTTP_BASE_URL", "http://127.0.0.1:28491"),
        ("DOCDEX_AUTH_TOKEN", "secret-token"),
    ]);
    let client = CliHttpClient::new()?;
    let req = client.request(Method::GET, "/healthz").build()?;
    let auth = req
        .headers()
        .get(reqwest::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert_eq!(auth, "Bearer secret-token");
    Ok(())
}

#[test]
fn with_repo_adds_repo_id_header() -> Result<(), Box<dyn std::error::Error>> {
    let _env = EnvGuard::set(&[("DOCDEX_HTTP_BASE_URL", "http://127.0.0.1:28491")]);
    let temp = TempDir::new()?;
    let client = CliHttpClient::new()?;
    let req = client.request(Method::GET, "/healthz");
    let req = client.with_repo(req, temp.path())?.build()?;
    let header = req
        .headers()
        .get("x-docdex-repo-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert!(!header.is_empty(), "expected repo id header");
    Ok(())
}

#[test]
fn resolve_base_url_with_lock_prefers_env() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let lock_path = temp.path().join("daemon.lock");
    let lock = crate::daemon::lock::acquire_lock_at_path(&lock_path, 4321)?;
    drop(lock);
    let _env = EnvGuard::set(&[
        ("DOCDEX_DAEMON_LOCK_PATH", lock_path.to_str().unwrap()),
        ("DOCDEX_HTTP_BASE_URL", "http://127.0.0.1:5555"),
    ]);
    let resolved = resolve_base_url_with_lock()?;
    assert_eq!(resolved, "http://127.0.0.1:5555");
    Ok(())
}

#[test]
fn resolve_base_url_with_lock_uses_lock_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let lock_path = temp.path().join("daemon.lock");
    let lock = crate::daemon::lock::acquire_lock_at_path(&lock_path, 4321)?;
    drop(lock);
    let _env = EnvGuard::set(&[
        ("DOCDEX_DAEMON_LOCK_PATH", lock_path.to_str().unwrap()),
        ("DOCDEX_HTTP_BASE_URL", ""),
    ]);
    let resolved = resolve_base_url_with_lock()?;
    assert_eq!(resolved, "http://127.0.0.1:4321");
    Ok(())
}
