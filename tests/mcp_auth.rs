mod common;

use serde_json::json;
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::TempDir;

fn docdex_bin() -> PathBuf {
    std::env::set_var("DOCDEX_CLI_LOCAL", "1");
    std::env::set_var("DOCDEX_MCP_SERVER_BIN", common::mcp_server_bin());
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn write_fixture_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(repo_root)?;
    fs::write(repo_root.join("README.md"), "# MCP Auth Fixture\n")?;
    Ok(())
}

fn run_index(state_root: &Path, repo_root: &Path) -> Result<(), Box<dyn Error>> {
    let output = Command::new(docdex_bin()).env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_STATE_DIR", state_root)
        .args(["index", "--repo", repo_root.to_string_lossy().as_ref()])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "docdexd index failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}

#[test]
fn mcp_initialize_requires_auth_token_when_configured() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_fixture_repo(repo.path())?;
    let state_root = TempDir::new()?;
    run_index(state_root.path(), repo.path())?;

    let mut child = Command::new(docdex_bin()).env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_STATE_DIR", state_root.path())
        .env("DOCDEX_AUTH_TOKEN", "secret-token")
        .args([
            "mcp",
            "--repo",
            repo.path().to_string_lossy().as_ref(),
            "--log",
            "warn",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let mut stdin = child.stdin.take().ok_or("failed to take MCP stdin")?;
    let stdout = child.stdout.take().ok_or("failed to take MCP stdout")?;
    let mut reader = BufReader::new(stdout);

    let init_missing = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    });
    writeln!(stdin, "{}", init_missing)?;
    stdin.flush()?;
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let resp: serde_json::Value = serde_json::from_str(line.trim())?;
    let code = resp
        .get("error")
        .and_then(|e| e.get("data"))
        .and_then(|d| d.get("code"))
        .and_then(|v| v.as_str());
    assert_eq!(code, Some("unauthorized"));

    let init_ok = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "initialize",
        "params": { "auth_token": "secret-token" }
    });
    writeln!(stdin, "{}", init_ok)?;
    stdin.flush()?;
    line.clear();
    reader.read_line(&mut line)?;
    let resp_ok: serde_json::Value = serde_json::from_str(line.trim())?;
    assert!(
        resp_ok.get("result").is_some(),
        "expected initialize success"
    );

    child.kill().ok();
    child.wait().ok();
    Ok(())
}
