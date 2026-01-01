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

#[test]
fn browser_list_reports_env_selection() {
    let temp = TempDir::new().expect("tempdir");
    let env_path = temp.path().join("env-browser");
    touch_file(&env_path);

    let mut cmd = Command::new(common::docdex_bin());
    cmd.args(["browser", "list"])
        .env("DOCDEX_CLI_LOCAL", "1")
        .env("HOME", temp.path())
        .env("DOCDEX_WEB_BROWSER", &env_path)
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_BROWSER_AUTO_INSTALL", "0");
    let output = cmd.assert().success().get_output().stdout.clone();
    let payload: Value = serde_json::from_slice(&output).expect("json");
    assert_eq!(
        payload["selected"]["path"],
        env_path.to_string_lossy().as_ref()
    );
    assert_eq!(payload["selected"]["source"], "env");
}

#[test]
#[cfg(not(target_os = "windows"))]
fn browser_setup_persists_detected_binary() {
    let temp = TempDir::new().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create bin dir");
    let chrome_path = bin_dir.join("google-chrome");
    touch_file(&chrome_path);

    let mut cmd = Command::new(common::docdex_bin());
    cmd.args(["browser", "setup"])
        .env("DOCDEX_CLI_LOCAL", "1")
        .env("HOME", temp.path())
        .env("PATH", &bin_dir)
        .env("DOCDEX_WEB_BROWSER", "")
        .env("DOCDEX_CHROME_PATH", "")
        .env("CHROME_PATH", "")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_BROWSER_AUTO_INSTALL", "0");
    let output = cmd.assert().success().get_output().stdout.clone();
    let payload: Value = serde_json::from_slice(&output).expect("json");
    assert_eq!(
        payload["selected"]["path"],
        chrome_path.to_string_lossy().as_ref()
    );
    assert_eq!(payload["selected"]["source"], "config");
}

#[test]
fn browser_install_is_noop_when_disabled() {
    let temp = TempDir::new().expect("tempdir");
    let mut cmd = Command::new(common::docdex_bin());
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
