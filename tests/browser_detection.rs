use docdexd::util::{detect_browser_binary, detect_browser_candidates, BrowserSource};
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
fn env_precedence_over_config_path() {
    let _lock = ENV_LOCK.lock().unwrap();
    let temp = TempDir::new().expect("tempdir");
    let env_path = temp.path().join("env-browser");
    let chrome_path = temp.path().join("chrome-browser");
    let config_path = temp.path().join("config-browser");
    touch_file(&env_path);
    touch_file(&chrome_path);
    touch_file(&config_path);

    let _env_browser = EnvGuard::set("DOCDEX_WEB_BROWSER", env_path.to_string_lossy().as_ref());
    let _chrome_path_env =
        EnvGuard::set("DOCDEX_CHROME_PATH", chrome_path.to_string_lossy().as_ref());
    let _chrome_path_env_alias = EnvGuard::unset("CHROME_PATH");

    let mut candidates = detect_browser_candidates(Some(&config_path));
    candidates.sort_by_key(|candidate| candidate.priority);

    assert!(!candidates.is_empty());
    assert_eq!(candidates[0].source, BrowserSource::Env);
    assert_eq!(candidates[0].path, env_path);
    assert_eq!(candidates[1].path, chrome_path);
    assert_eq!(candidates[2].path, config_path);
}

#[test]
fn detect_browser_binary_prefers_chromium_manifest_over_system() {
    let _lock = ENV_LOCK.lock().unwrap();
    let Some(platform) = current_managed_platform() else {
        return;
    };
    let temp = TempDir::new().expect("tempdir");
    let chromium_path = managed_chromium_path(temp.path(), platform);
    touch_file(&chromium_path);
    write_chromium_manifest(temp.path(), &chromium_path, platform);

    let bin_dir = temp.path().join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create bin dir");
    let chrome_path = bin_dir.join(command_name("chromium"));
    touch_file(&chrome_path);

    let _env_browser = EnvGuard::unset("DOCDEX_WEB_BROWSER");
    let _chrome_path_env = EnvGuard::unset("DOCDEX_CHROME_PATH");
    let _chrome_path_env_alias = EnvGuard::unset("CHROME_PATH");
    let _home = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    let _state_dir = EnvGuard::unset("DOCDEX_STATE_DIR");
    let original_path = std::env::var_os("PATH").unwrap_or_else(|| OsString::new());
    std::env::set_var("PATH", &bin_dir);

    let candidate = detect_browser_binary(None).expect("expected browser candidate");
    assert_eq!(candidate.source, BrowserSource::AutoInstall);
    assert_eq!(candidate.path, chromium_path);

    std::env::set_var("PATH", original_path);
}

#[test]
#[cfg(not(target_os = "windows"))]
fn detect_browser_binary_uses_which_when_no_env() {
    let _lock = ENV_LOCK.lock().unwrap();
    let temp = TempDir::new().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create bin dir");
    let chrome_path = bin_dir.join("chromium");
    touch_file(&chrome_path);

    let _env_browser = EnvGuard::unset("DOCDEX_WEB_BROWSER");
    let _chrome_path_env = EnvGuard::unset("DOCDEX_CHROME_PATH");
    let _chrome_path_env_alias = EnvGuard::unset("CHROME_PATH");
    let _home = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    let _user = EnvGuard::set("USERPROFILE", temp.path().to_string_lossy().as_ref());
    let original_path = std::env::var_os("PATH").unwrap_or_else(|| OsString::new());
    std::env::set_var("PATH", &bin_dir);

    let candidate = detect_browser_binary(None).expect("expected browser candidate");
    assert_eq!(candidate.source, BrowserSource::Which);
    assert_eq!(candidate.path, chrome_path);

    std::env::set_var("PATH", original_path);
}

#[test]
fn detect_browser_binary_prefers_docdex_web_browser_env() {
    let _lock = ENV_LOCK.lock().unwrap();
    let temp = TempDir::new().expect("tempdir");
    let env_path = temp.path().join("env-browser");
    touch_file(&env_path);

    let _env_browser = EnvGuard::set("DOCDEX_WEB_BROWSER", env_path.to_string_lossy().as_ref());
    let _chrome_path_env = EnvGuard::unset("DOCDEX_CHROME_PATH");
    let _chrome_path_env_alias = EnvGuard::unset("CHROME_PATH");

    let candidate = detect_browser_binary(None).expect("expected browser candidate");
    assert_eq!(candidate.source, BrowserSource::Env);
    assert_eq!(candidate.path, env_path);
}

#[test]
fn detect_browser_candidates_preserve_command_order() {
    let _lock = ENV_LOCK.lock().unwrap();
    let temp = TempDir::new().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create bin dir");
    let chromium_path = bin_dir.join(command_name("chromium"));
    let chromium_browser_path = bin_dir.join(command_name("chromium-browser"));
    touch_file(&chromium_path);
    touch_file(&chromium_browser_path);

    let _env_browser = EnvGuard::unset("DOCDEX_WEB_BROWSER");
    let _chrome_path_env = EnvGuard::unset("DOCDEX_CHROME_PATH");
    let _chrome_path_env_alias = EnvGuard::unset("CHROME_PATH");
    let original_path = std::env::var_os("PATH").unwrap_or_else(|| OsString::new());
    std::env::set_var("PATH", &bin_dir);

    let mut candidates = detect_browser_candidates(None);
    candidates.sort_by_key(|candidate| candidate.priority);
    let which_candidates: Vec<_> = candidates
        .iter()
        .filter(|candidate| candidate.source == BrowserSource::Which)
        .collect();
    assert!(which_candidates.len() >= 2);
    assert_eq!(which_candidates[0].path, chromium_path);
    assert_eq!(which_candidates[1].path, chromium_browser_path);

    std::env::set_var("PATH", original_path);
}

fn command_name(base: &str) -> String {
    if cfg!(target_os = "windows") {
        format!("{base}.exe")
    } else {
        base.to_string()
    }
}
