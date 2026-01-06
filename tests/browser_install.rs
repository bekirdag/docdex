use docdexd::web::browser_install;
use once_cell::sync::Lazy;
use std::ffi::OsString;
use std::path::Path;
use std::sync::Mutex;
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

    fn unset(key: &'static str) -> Self {
        let prev = std::env::var_os(key);
        std::env::remove_var(key);
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

fn touch_file(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).expect("create parent dir");
    std::fs::write(path, b"#!/bin/sh\necho test\n").expect("write file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path).expect("metadata").permissions();
        perms.set_mode(perms.mode() | 0o111);
        std::fs::set_permissions(path, perms).expect("chmod");
    }
}

fn write_playwright_manifest(root: &Path, chromium_path: &Path) {
    let manifest_dir = root.join(".docdex").join("state").join("bin").join("playwright");
    std::fs::create_dir_all(&manifest_dir).expect("create manifest dir");
    let payload = serde_json::json!({
        "installed_at": "2024-01-01T00:00:00Z",
        "browsers_path": manifest_dir.to_string_lossy(),
        "playwright_version": "1.2.3",
        "browsers": [
            { "name": "chromium", "version": "12345", "path": chromium_path }
        ]
    });
    std::fs::write(manifest_dir.join("manifest.json"), payload.to_string()).expect("write manifest");
}

#[test]
fn browser_install_respects_opt_out() {
    let _lock = ENV_LOCK.lock().unwrap();
    let _auto_install = EnvGuard::set("DOCDEX_BROWSER_AUTO_INSTALL", "0");
    let result = browser_install::install_if_missing(true);
    assert!(matches!(result, Ok(None)));
}

#[test]
fn browser_install_reads_playwright_manifest() {
    let _lock = ENV_LOCK.lock().unwrap();
    let temp = TempDir::new().expect("tempdir");
    let chromium_path = temp.path().join("pw-chromium");
    touch_file(&chromium_path);
    write_playwright_manifest(temp.path(), &chromium_path);

    let _home = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    let _auto_install = EnvGuard::set("DOCDEX_BROWSER_AUTO_INSTALL", "1");
    let _pw_path = EnvGuard::unset("PLAYWRIGHT_BROWSERS_PATH");

    let result = browser_install::install_if_missing(true).expect("install ok");
    let Some(result) = result else {
        panic!("expected install result");
    };
    assert_eq!(result.path, chromium_path);
    assert_eq!(result.version, "12345");
}
