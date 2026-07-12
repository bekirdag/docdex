use assert_cmd::Command;
use serde_json::Value;
use std::path::Path;
use tempfile::TempDir;

mod common;

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
fn browser_list_reports_chromium_manifest() {
    let Some(platform) = current_managed_platform() else {
        return;
    };
    let temp = TempDir::new().expect("tempdir");
    let chromium_path = managed_chromium_path(temp.path(), platform);
    touch_file(&chromium_path);
    write_chromium_manifest(temp.path(), &chromium_path, platform);

    let mut cmd = Command::new(common::docdex_bin());
    cmd.env("DOCDEX_WEB_ENABLED", "0");
    cmd.args(["browser", "list"])
        .env("DOCDEX_CLI_LOCAL", "1")
        .env("HOME", temp.path())
        .env_remove("DOCDEX_CONFIG_PATH")
        .env_remove("DOCDEX_GLOBAL_STATE_DIR")
        .env_remove("DOCDEX_STATE_DIR")
        .env("DOCDEX_WEB_BROWSER", "")
        .env("DOCDEX_CHROME_PATH", "")
        .env("CHROME_PATH", "")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_BROWSER_AUTO_INSTALL", "0");
    let output = cmd.assert().success().get_output().stdout.clone();
    let payload: Value = serde_json::from_slice(&output).expect("json");
    assert_eq!(
        payload["selected"]["path"],
        chromium_path.to_string_lossy().as_ref()
    );
    assert_eq!(payload["selected"]["source"], "auto_install");
}

#[test]
#[cfg(not(target_os = "windows"))]
fn browser_setup_reports_chromium_manifest() {
    let Some(platform) = current_managed_platform() else {
        return;
    };
    let temp = TempDir::new().expect("tempdir");
    let chromium_path = managed_chromium_path(temp.path(), platform);
    touch_file(&chromium_path);
    write_chromium_manifest(temp.path(), &chromium_path, platform);

    let mut cmd = Command::new(common::docdex_bin());
    cmd.env("DOCDEX_WEB_ENABLED", "0");
    cmd.args(["browser", "setup"])
        .env("DOCDEX_CLI_LOCAL", "1")
        .env("HOME", temp.path())
        .env_remove("DOCDEX_CONFIG_PATH")
        .env_remove("DOCDEX_GLOBAL_STATE_DIR")
        .env_remove("DOCDEX_STATE_DIR")
        .env("DOCDEX_WEB_BROWSER", "")
        .env("DOCDEX_CHROME_PATH", "")
        .env("CHROME_PATH", "")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_BROWSER_AUTO_INSTALL", "0");
    let output = cmd.assert().success().get_output().stdout.clone();
    let payload: Value = serde_json::from_slice(&output).expect("json");
    assert_eq!(
        payload["selected"]["path"],
        chromium_path.to_string_lossy().as_ref()
    );
    assert_eq!(payload["selected"]["source"], "auto_install");
}

#[test]
fn browser_install_is_noop_when_disabled() {
    let temp = TempDir::new().expect("tempdir");
    let mut cmd = Command::new(common::docdex_bin());
    cmd.env("DOCDEX_WEB_ENABLED", "0");
    cmd.args(["browser", "install"])
        .env("DOCDEX_CLI_LOCAL", "1")
        .env("HOME", temp.path())
        .env_remove("DOCDEX_CONFIG_PATH")
        .env_remove("DOCDEX_GLOBAL_STATE_DIR")
        .env_remove("DOCDEX_STATE_DIR")
        .env("DOCDEX_WEB_BROWSER", "")
        .env("DOCDEX_CHROME_PATH", "")
        .env("CHROME_PATH", "")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_BROWSER_AUTO_INSTALL", "0");
    let output = cmd.assert().success().get_output().stdout.clone();
    let payload: Value = serde_json::from_slice(&output).expect("json");
    assert_eq!(payload["installed"], false);
}
