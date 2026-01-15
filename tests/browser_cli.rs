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

fn write_chromium_manifest(root: &Path, chromium_path: &Path) {
    let manifest_dir = root
        .join(".docdex")
        .join("state")
        .join("bin")
        .join("chromium");
    std::fs::create_dir_all(&manifest_dir).expect("create manifest dir");
    let payload = serde_json::json!({
        "installed_at": "2024-01-01T00:00:00Z",
        "version": "12345",
        "platform": "linux64",
        "download_url": "https://example.com/chromium.zip",
        "path": chromium_path,
    });
    std::fs::write(manifest_dir.join("manifest.json"), payload.to_string())
        .expect("write manifest");
}

#[test]
fn browser_list_reports_chromium_manifest() {
    let temp = TempDir::new().expect("tempdir");
    let chromium_path = temp.path().join("docdex-chromium");
    touch_file(&chromium_path);
    write_chromium_manifest(temp.path(), &chromium_path);

    let mut cmd = Command::new(common::docdex_bin());
    cmd.env("DOCDEX_WEB_ENABLED", "0");
    cmd.args(["browser", "list"])
        .env("DOCDEX_CLI_LOCAL", "1")
        .env("HOME", temp.path())
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
    let temp = TempDir::new().expect("tempdir");
    let chromium_path = temp.path().join("docdex-chromium");
    touch_file(&chromium_path);
    write_chromium_manifest(temp.path(), &chromium_path);

    let mut cmd = Command::new(common::docdex_bin());
    cmd.env("DOCDEX_WEB_ENABLED", "0");
    cmd.args(["browser", "setup"])
        .env("DOCDEX_CLI_LOCAL", "1")
        .env("HOME", temp.path())
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
        .env("DOCDEX_WEB_BROWSER", "")
        .env("DOCDEX_CHROME_PATH", "")
        .env("CHROME_PATH", "")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_BROWSER_AUTO_INSTALL", "0");
    let output = cmd.assert().success().get_output().stdout.clone();
    let payload: Value = serde_json::from_slice(&output).expect("json");
    assert_eq!(payload["installed"], false);
}
