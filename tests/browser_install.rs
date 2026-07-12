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

fn current_managed_platform() -> Option<&'static str> {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Some("mac-arm64")
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        Some("mac-x64")
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some("linux64")
    } else if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        Some("win64")
    } else {
        None
    }
}

fn managed_chromium_path(root: &Path, platform: &str) -> std::path::PathBuf {
    let rel = match platform {
        "mac-arm64" => "chrome-headless-shell-mac-arm64/chrome-headless-shell",
        "mac-x64" => "chrome-headless-shell-mac-x64/chrome-headless-shell",
        "linux64" => "chrome-headless-shell-linux64/chrome-headless-shell",
        "win64" => "chrome-headless-shell-win64/chrome-headless-shell.exe",
        _ => panic!("unsupported test platform"),
    };
    root.join(".docdex")
        .join("state")
        .join("bin")
        .join("chromium")
        .join(rel)
}

fn write_chromium_manifest(root: &Path, chromium_path: &Path, platform: &str) {
    let manifest_dir = root
        .join(".docdex")
        .join("state")
        .join("bin")
        .join("chromium");
    std::fs::create_dir_all(&manifest_dir).expect("create manifest dir");
    let version = "123.0.4567.8";
    let checked_at = chrono::Utc::now().to_rfc3339();
    let payload = serde_json::json!({
        "installed_at": checked_at.clone(),
        "last_checked_at": checked_at,
        "version": version,
        "platform": platform,
        "artifact": "chrome-headless-shell",
        "download_url": format!("https://storage.googleapis.com/chrome-for-testing-public/{version}/{platform}/chrome-headless-shell-{platform}.zip"),
        "path": chromium_path,
    });
    std::fs::write(manifest_dir.join("manifest.json"), payload.to_string())
        .expect("write manifest");
}

#[test]
fn browser_install_respects_opt_out() {
    let _lock = ENV_LOCK.lock().unwrap();
    let _auto_install = EnvGuard::set("DOCDEX_BROWSER_AUTO_INSTALL", "0");
    let result = browser_install::install_if_missing(true);
    assert!(matches!(result, Ok(None)));
}

#[test]
fn browser_install_reads_chromium_manifest() {
    let _lock = ENV_LOCK.lock().unwrap();
    let Some(platform) = current_managed_platform() else {
        return;
    };
    let temp = TempDir::new().expect("tempdir");
    let chromium_path = managed_chromium_path(temp.path(), platform);
    touch_file(&chromium_path);
    write_chromium_manifest(temp.path(), &chromium_path, platform);

    let _home = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    let _state_dir = EnvGuard::unset("DOCDEX_STATE_DIR");
    let _auto_install = EnvGuard::set("DOCDEX_BROWSER_AUTO_INSTALL", "1");
    let _auto_update = EnvGuard::set("DOCDEX_BROWSER_AUTO_UPDATE", "1");
    let _update_interval = EnvGuard::set("DOCDEX_BROWSER_UPDATE_CHECK_INTERVAL_SECS", "86400");

    let result = browser_install::install_if_missing(true).expect("install ok");
    let Some(result) = result else {
        panic!("expected install result");
    };
    assert_eq!(result.path, chromium_path);
    assert_eq!(result.version, "123.0.4567.8");
}

#[test]
fn browser_install_rejects_an_oversized_managed_manifest() {
    let _lock = ENV_LOCK.lock().unwrap();
    let Some(platform) = current_managed_platform() else {
        return;
    };
    let temp = TempDir::new().expect("tempdir");
    let chromium_path = managed_chromium_path(temp.path(), platform);
    touch_file(&chromium_path);
    write_chromium_manifest(temp.path(), &chromium_path, platform);
    let manifest_path = temp.path().join(".docdex/state/bin/chromium/manifest.json");
    let mut payload = std::fs::read(&manifest_path).expect("read valid manifest");
    payload.extend(std::iter::repeat_n(b' ', 70 * 1024));
    std::fs::write(&manifest_path, payload).expect("write oversized valid manifest");
    let _home = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    let _state_dir = EnvGuard::unset("DOCDEX_STATE_DIR");

    let status = browser_install::chromium_install_status();
    assert!(!status.installed);
    assert!(status.path.is_none());
    assert!(status.version.is_none());
}
