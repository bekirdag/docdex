use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

mod common;

#[test]
fn check_reports_browser_fields() {
    let temp = TempDir::new().expect("tempdir");
    let config_dir = temp.path().join(".docdex");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    let config_path = config_dir.join("config.toml");
    std::fs::write(
        &config_path,
        r#"[server]
http_bind_addr = "127.0.0.1:0"
enable_mcp = false

[llm]
provider = "openai"
"#,
    )
    .expect("write config");

    let mut cmd = Command::new(common::docdex_bin());
    cmd.env("DOCDEX_WEB_ENABLED", "0");
    cmd.args(["check"])
        .env("DOCDEX_CLI_LOCAL", "1")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_ENABLE_MCP", "0")
        .env("DOCDEX_LLM_AGENT", "test")
        .env("HOME", temp.path())
        .env("USERPROFILE", temp.path());
    let output = cmd.assert().success().get_output().stdout.clone();
    let payload: Value = serde_json::from_slice(&output).expect("json");
    let checks = payload["checks"].as_array().expect("checks array");
    let chrome = checks
        .iter()
        .find(|entry| entry["name"] == "chrome")
        .expect("chrome check");
    let details = chrome["details"].as_object().expect("details object");
    assert!(details.contains_key("auto_install_enabled"));
}
