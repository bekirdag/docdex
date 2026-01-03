use docdexd::web::browser_install;
use once_cell::sync::Lazy;
use std::ffi::OsString;
use std::sync::Mutex;
#[cfg(target_os = "linux")]
use tempfile::TempDir;

static ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

struct EnvGuard {
    key: &'static str,
    prev: Option<OsString>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let prev = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, prev }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(value) = self.prev.take() {
            std::env::set_var(self.key, value);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

#[test]
fn browser_install_respects_opt_out() {
    let _lock = ENV_LOCK.lock().unwrap();
    let _auto_install = EnvGuard::set("DOCDEX_BROWSER_AUTO_INSTALL", "0");
    let result = browser_install::install_if_missing(true);
    assert!(matches!(result, Ok(None)));
}

#[test]
#[cfg(target_os = "linux")]
fn browser_install_downloads_fixture() {
    let _lock = ENV_LOCK.lock().unwrap();
    let enabled = std::env::var("DOCDEX_TEST_ENABLE_BROWSER_INSTALL")
        .ok()
        .map(|value| value.trim().to_ascii_lowercase())
        .map(|value| matches!(value.as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);
    if !enabled {
        return;
    }

    let temp = TempDir::new().expect("tempdir");
    let _home = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    let _auto_install = EnvGuard::set("DOCDEX_BROWSER_AUTO_INSTALL", "1");

    let zip_bytes = build_zip_fixture();
    let checksum = sha256_hex(&zip_bytes);
    let (base_url, shutdown) = spawn_zip_server(zip_bytes);

    let _base = EnvGuard::set("DOCDEX_BROWSER_DOWNLOAD_BASE", &base_url);
    let _version = EnvGuard::set("DOCDEX_BROWSER_VERSION", "fixture");
    let _sha = EnvGuard::set("DOCDEX_BROWSER_SHA256", &checksum);

    let result = browser_install::install_if_missing(true).expect("install ok");
    shutdown();
    let Some(result) = result else {
        panic!("expected install result");
    };
    assert!(result.path.is_file());

    let manifest_path = temp.path().join(".docdex/state/bin/chromium/manifest.json");
    let manifest = std::fs::read_to_string(&manifest_path).expect("read manifest");
    let parsed: serde_json::Value = serde_json::from_str(&manifest).expect("manifest json");
    assert_eq!(
        parsed.get("sha256").and_then(|value| value.as_str()),
        Some(checksum.as_str())
    );
    assert_eq!(
        parsed.get("path").and_then(|value| value.as_str()),
        Some(result.path.to_string_lossy().as_ref())
    );
}

#[cfg(target_os = "linux")]
fn build_zip_fixture() -> Vec<u8> {
    use std::io::Write;
    use zip::write::FileOptions;
    let cursor = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(cursor);
    writer
        .add_directory("chrome-linux64/", FileOptions::default())
        .expect("add dir");
    writer
        .start_file("chrome-linux64/chrome", FileOptions::default())
        .expect("start file");
    writer
        .write_all(b"#!/bin/sh\necho fixture\n")
        .expect("write");
    let cursor = writer.finish().expect("finish zip");
    cursor.into_inner()
}

#[cfg(target_os = "linux")]
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(target_os = "linux")]
fn spawn_zip_server(bytes: Vec<u8>) -> (String, impl FnOnce()) {
    use axum::{routing::get, Router};
    use std::net::TcpListener;
    use tokio::sync::oneshot;

    let std_listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = std_listener.local_addr().expect("addr");
    let (tx, rx) = oneshot::channel::<()>();
    let join = std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(async move {
            let payload = bytes;
            let app = Router::new().route(
                "/fixture/linux64/chrome-linux64.zip",
                get(move || async move { payload.clone() }),
            );
            let listener = tokio::net::TcpListener::from_std(std_listener).expect("listener");
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = rx.await;
                })
                .await
                .expect("serve");
        });
    });

    let base_url = format!("http://{}", addr);
    let shutdown = move || {
        let _ = tx.send(());
        let _ = join.join();
    };
    (base_url, shutdown)
}
