mod common;

use serde_json::Value;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn docdex_bin() -> PathBuf {
    std::env::set_var("DOCDEX_CLI_LOCAL", "1");
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn write_config(home: &Path, state_root: &Path, enable_mcp: bool) -> Result<(), Box<dyn Error>> {
    let config_dir = home.join(".docdex");
    fs::create_dir_all(&config_dir)?;
    let payload = format!(
        r#"[core]
global_state_dir = "{}"

[llm]
provider = "noop"
default_model = "noop"
embedding_model = "noop"
max_answer_tokens = 128

[server]
enable_mcp = {}
http_bind_addr = "127.0.0.1:0"
"#,
        crate::common::toml_path(state_root),
        enable_mcp
    );
    fs::write(config_dir.join("config.toml"), payload)?;
    Ok(())
}

fn parse_report(output: &[u8]) -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::from_slice(output)?)
}

fn temp_exec_dir() -> Result<TempDir, Box<dyn Error>> {
    let base = std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir());
    Ok(TempDir::new_in(base)?)
}

fn find_check<'a>(report: &'a Value, name: &str) -> Option<&'a Value> {
    report
        .get("checks")
        .and_then(|v| v.as_array())
        .and_then(|checks| {
            checks
                .iter()
                .find(|item| item.get("name").and_then(|v| v.as_str()) == Some(name))
        })
}

#[test]
fn check_skips_mcp_when_disabled() -> Result<(), Box<dyn Error>> {
    let home = TempDir::new()?;
    let state_root = TempDir::new()?;
    write_config(home.path(), state_root.path(), false)?;

    let output = Command::new(docdex_bin())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("HOME", home.path())
        .env("DOCDEX_LLM_AGENT", "test")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env_remove("DOCDEX_ENABLE_MCP")
        .arg("check")
        .output()?;

    assert!(output.status.success(), "docdexd check should succeed");
    let report = parse_report(&output.stdout)?;
    let check = find_check(&report, "mcp_ready").ok_or("missing mcp_ready check")?;
    assert_eq!(
        check.get("status").and_then(|v| v.as_str()),
        Some("skipped")
    );
    Ok(())
}

#[test]
fn check_fails_when_mcp_enabled_missing_binary() -> Result<(), Box<dyn Error>> {
    let home = TempDir::new()?;
    let state_root = TempDir::new()?;
    write_config(home.path(), state_root.path(), true)?;
    let missing_bin = home.path().join("missing-mcp-server");

    let output = Command::new(docdex_bin())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("HOME", home.path())
        .env("DOCDEX_LLM_AGENT", "test")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_MCP_SERVER_BIN", &missing_bin)
        .env_remove("DOCDEX_ENABLE_MCP")
        .arg("check")
        .output()?;

    assert!(
        !output.status.success(),
        "docdexd check should fail when MCP binary is missing"
    );
    let report = parse_report(&output.stdout)?;
    let check = find_check(&report, "mcp_ready").ok_or("missing mcp_ready check")?;
    assert_eq!(check.get("status").and_then(|v| v.as_str()), Some("fail"));
    Ok(())
}

#[test]
fn check_passes_when_mcp_enabled_binary_resolves() -> Result<(), Box<dyn Error>> {
    let home = TempDir::new()?;
    let state_root = TempDir::new()?;
    write_config(home.path(), state_root.path(), true)?;
    let bin_path = home.path().join("docdex-mcp-server");
    fs::write(&bin_path, "")?;

    let output = Command::new(docdex_bin())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("HOME", home.path())
        .env("DOCDEX_LLM_AGENT", "test")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_MCP_SERVER_BIN", &bin_path)
        .env_remove("DOCDEX_ENABLE_MCP")
        .arg("check")
        .output()?;

    assert!(output.status.success(), "docdexd check should succeed");
    let report = parse_report(&output.stdout)?;
    let check = find_check(&report, "mcp_ready").ok_or("missing mcp_ready check")?;
    assert_eq!(check.get("status").and_then(|v| v.as_str()), Some("ok"));
    Ok(())
}

#[test]
fn check_spawn_fails_when_mcp_binary_exits() -> Result<(), Box<dyn Error>> {
    let home = TempDir::new()?;
    let state_root = TempDir::new()?;
    write_config(home.path(), state_root.path(), true)?;
    let bin_dir = temp_exec_dir()?;
    let bin_path = bin_dir.path().join("docdex-mcp-server");
    fs::write(&bin_path, "#!/bin/sh\nexit 1\n")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&bin_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&bin_path, perms)?;
    }

    let output = Command::new(docdex_bin())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("HOME", home.path())
        .env("DOCDEX_LLM_AGENT", "test")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_MCP_SERVER_BIN", &bin_path)
        .env("DOCDEX_CHECK_MCP_SPAWN", "1")
        .env_remove("DOCDEX_ENABLE_MCP")
        .arg("check")
        .output()?;

    assert!(
        !output.status.success(),
        "docdexd check should fail when MCP spawn check fails"
    );
    let report = parse_report(&output.stdout)?;
    let check = find_check(&report, "mcp_ready").ok_or("missing mcp_ready check")?;
    assert_eq!(check.get("status").and_then(|v| v.as_str()), Some("fail"));
    let spawn_status = check
        .get("details")
        .and_then(|v| v.get("spawn_details"))
        .and_then(|v| v.get("spawn_status"))
        .and_then(|v| v.as_str());
    assert_eq!(spawn_status, Some("exit"));
    Ok(())
}

#[test]
fn check_spawn_succeeds_when_mcp_binary_exits_zero() -> Result<(), Box<dyn Error>> {
    let home = TempDir::new()?;
    let state_root = TempDir::new()?;
    write_config(home.path(), state_root.path(), true)?;
    let bin_dir = temp_exec_dir()?;
    let bin_path = bin_dir.path().join("docdex-mcp-server");
    fs::write(&bin_path, "#!/bin/sh\nexit 0\n")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&bin_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&bin_path, perms)?;
    }

    let output = Command::new(docdex_bin())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("HOME", home.path())
        .env("DOCDEX_LLM_AGENT", "test")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_MCP_SERVER_BIN", &bin_path)
        .env("DOCDEX_CHECK_MCP_SPAWN", "1")
        .env_remove("DOCDEX_ENABLE_MCP")
        .arg("check")
        .output()?;

    assert!(
        output.status.success(),
        "docdexd check should succeed when MCP spawn check passes"
    );
    let report = parse_report(&output.stdout)?;
    let check = find_check(&report, "mcp_ready").ok_or("missing mcp_ready check")?;
    assert_eq!(check.get("status").and_then(|v| v.as_str()), Some("ok"));
    let spawn_status = check
        .get("details")
        .and_then(|v| v.get("spawn_details"))
        .and_then(|v| v.get("spawn_status"))
        .and_then(|v| v.as_str());
    assert_eq!(spawn_status, Some("ok"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn check_spawn_times_out_when_mcp_binary_hangs() -> Result<(), Box<dyn Error>> {
    let home = TempDir::new()?;
    let state_root = TempDir::new()?;
    write_config(home.path(), state_root.path(), true)?;
    let bin_dir = temp_exec_dir()?;
    let bin_path = bin_dir.path().join("docdex-mcp-server");
    fs::write(&bin_path, "#!/bin/sh\nsleep 2\n")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&bin_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&bin_path, perms)?;
    }

    let output = Command::new(docdex_bin())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("HOME", home.path())
        .env("DOCDEX_LLM_AGENT", "test")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_MCP_SERVER_BIN", &bin_path)
        .env("DOCDEX_CHECK_MCP_SPAWN", "1")
        .env("DOCDEX_CHECK_MCP_SPAWN_TIMEOUT_MS", "50")
        .env_remove("DOCDEX_ENABLE_MCP")
        .arg("check")
        .output()?;

    assert!(
        !output.status.success(),
        "docdexd check should fail when MCP spawn check times out"
    );
    let report = parse_report(&output.stdout)?;
    let check = find_check(&report, "mcp_ready").ok_or("missing mcp_ready check")?;
    assert_eq!(check.get("status").and_then(|v| v.as_str()), Some("fail"));
    let spawn_status = check
        .get("details")
        .and_then(|v| v.get("spawn_details"))
        .and_then(|v| v.get("spawn_status"))
        .and_then(|v| v.as_str());
    assert_eq!(spawn_status, Some("timeout"));
    Ok(())
}
