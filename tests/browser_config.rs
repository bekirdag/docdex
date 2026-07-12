#![cfg(not(target_os = "windows"))]

use docdexd::config;
use once_cell::sync::Lazy;
use serde_json::json;
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
    } else {
        None
    }
}

fn managed_chromium_path(root: &Path, platform: &str) -> std::path::PathBuf {
    let rel = match platform {
        "mac-arm64" => "chrome-headless-shell-mac-arm64/chrome-headless-shell",
        "mac-x64" => "chrome-headless-shell-mac-x64/chrome-headless-shell",
        "linux64" => "chrome-headless-shell-linux64/chrome-headless-shell",
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
    let payload = json!({
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
#[cfg(not(target_os = "windows"))]
fn config_persists_detected_browser_path() {
    let _lock = ENV_LOCK.lock().unwrap();
    let Some(platform) = current_managed_platform() else {
        return;
    };
    let temp = TempDir::new().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create bin dir");
    let chrome_path = bin_dir.join("google-chrome");
    touch_file(&chrome_path);

    let chromium_path = managed_chromium_path(temp.path(), platform);
    touch_file(&chromium_path);
    write_chromium_manifest(temp.path(), &chromium_path, platform);

    let _home = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    let _state_dir = EnvGuard::unset("DOCDEX_STATE_DIR");
    let _path_guard = EnvGuard::set("PATH", bin_dir.to_string_lossy().as_ref());
    let _auto_install = EnvGuard::set("DOCDEX_BROWSER_AUTO_INSTALL", "0");
    let _env_browser = EnvGuard::unset("DOCDEX_WEB_BROWSER");
    let _chrome_path_env = EnvGuard::unset("DOCDEX_CHROME_PATH");
    let _chrome_path_env_alias = EnvGuard::unset("CHROME_PATH");

    let config_path = temp.path().join("docdex.toml");
    let config = config::load_config_from_path(&config_path).expect("load config");
    assert_eq!(
        config.web.scraper.chrome_binary_path.as_ref(),
        Some(&chromium_path)
    );
    assert_eq!(config.web.scraper.browser_kind.as_deref(), Some("chromium"));

    let reload = config::load_config_from_path(&config_path).expect("reload config");
    assert_eq!(
        reload.web.scraper.chrome_binary_path.as_ref(),
        Some(&chromium_path)
    );
}

#[test]
#[cfg(not(target_os = "windows"))]
fn config_preserves_valid_explicit_browser_without_managed_manifest() {
    let _lock = ENV_LOCK.lock().unwrap();
    let temp = TempDir::new().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create bin dir");
    let configured_path = bin_dir.join("custom-chrome");
    touch_file(&configured_path);

    let _home = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    let _state_dir = EnvGuard::unset("DOCDEX_STATE_DIR");
    let _path_guard = EnvGuard::set("PATH", bin_dir.to_string_lossy().as_ref());
    let _auto_install = EnvGuard::set("DOCDEX_BROWSER_AUTO_INSTALL", "0");
    let _env_browser = EnvGuard::unset("DOCDEX_WEB_BROWSER");
    let _chrome_path_env = EnvGuard::unset("DOCDEX_CHROME_PATH");
    let _chrome_path_env_alias = EnvGuard::unset("CHROME_PATH");

    let config_path = temp.path().join("docdex.toml");
    let payload = format!(
        "[web.scraper]\nchrome_binary_path = \"{}\"\nbrowser_kind = \"chrome\"\n",
        configured_path.to_string_lossy()
    );
    std::fs::write(&config_path, payload).expect("write config");

    let config = config::load_config_from_path(&config_path).expect("load config");
    assert_eq!(
        config.web.scraper.chrome_binary_path.as_ref(),
        Some(&configured_path)
    );
    assert_eq!(config.web.scraper.browser_kind.as_deref(), Some("chrome"));
}

#[test]
#[cfg(not(target_os = "windows"))]
fn config_replaces_invalid_explicit_path_with_managed_browser() {
    let _lock = ENV_LOCK.lock().unwrap();
    let Some(platform) = current_managed_platform() else {
        return;
    };
    let temp = TempDir::new().expect("tempdir");
    let configured_path = temp.path().join("missing-chrome");
    let managed_path = managed_chromium_path(temp.path(), platform);
    touch_file(&managed_path);
    write_chromium_manifest(temp.path(), &managed_path, platform);

    let _home = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    let _state_dir = EnvGuard::unset("DOCDEX_STATE_DIR");
    let _auto_install = EnvGuard::set("DOCDEX_BROWSER_AUTO_INSTALL", "0");
    let _env_browser = EnvGuard::unset("DOCDEX_WEB_BROWSER");
    let _chrome_path_env = EnvGuard::unset("DOCDEX_CHROME_PATH");
    let _chrome_path_env_alias = EnvGuard::unset("CHROME_PATH");

    let config_path = temp.path().join("docdex.toml");
    let payload = format!(
        "[web.scraper]\nchrome_binary_path = \"{}\"\nbrowser_kind = \"chrome\"\n",
        configured_path.to_string_lossy()
    );
    std::fs::write(&config_path, payload).expect("write config");

    let config = config::load_config_from_path(&config_path).expect("load config");
    assert_eq!(
        config.web.scraper.chrome_binary_path.as_ref(),
        Some(&managed_path)
    );
    assert_eq!(config.web.scraper.browser_kind.as_deref(), Some("chrome"));
}

#[test]
#[cfg(not(target_os = "windows"))]
fn config_preserves_user_data_dir() {
    let _lock = ENV_LOCK.lock().unwrap();
    let temp = TempDir::new().expect("tempdir");
    let user_dir = temp.path().join("profiles").join("chrome");
    std::fs::create_dir_all(&user_dir).expect("create profile dir");

    let _home = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    let _auto_install = EnvGuard::set("DOCDEX_BROWSER_AUTO_INSTALL", "0");
    let _env_browser = EnvGuard::unset("DOCDEX_WEB_BROWSER");
    let _chrome_path_env = EnvGuard::unset("DOCDEX_CHROME_PATH");
    let _chrome_path_env_alias = EnvGuard::unset("CHROME_PATH");

    let config_path = temp.path().join("docdex.toml");
    let payload = format!(
        "[web.scraper]\nuser_data_dir = \"{}\"\n",
        user_dir.to_string_lossy()
    );
    std::fs::write(&config_path, payload).expect("write config");

    let config = config::load_config_from_path(&config_path).expect("load config");
    assert_eq!(config.web.scraper.user_data_dir.as_ref(), Some(&user_dir));
}
