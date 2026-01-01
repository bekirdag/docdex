mod common;

use common::{docdex_bin, mcp_server_bin, pick_free_port, wait_for_health, MockOllama};
use docdexd::profiles::{PreferenceCategory, ProfileManager};
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use tempfile::TempDir;

fn write_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(repo_root.join("docs"))?;
    fs::write(repo_root.join("docs").join("readme.md"), "# Repo\n")?;
    Ok(())
}

fn write_config(
    home_dir: &Path,
    global_state_dir: &Path,
    llm_base_url: &str,
) -> Result<(), Box<dyn Error>> {
    let config_dir = home_dir.join(".docdex");
    fs::create_dir_all(&config_dir)?;
    let config_path = config_dir.join("config.toml");
    let payload = format!(
        "[core]\nglobal_state_dir = \"{}\"\n\n[llm]\nbase_url = \"{}\"\ndefault_model = \"fake-model\"\n\n[memory.profile]\nembedding_dim = 4\nembedding_model = \"fake-embed\"\n",
        crate::common::toml_path(global_state_dir),
        llm_base_url,
    );
    fs::write(config_path, payload)?;
    Ok(())
}

fn seed_profile(global_state_dir: &Path, agent_id: &str) -> Result<(), Box<dyn Error>> {
    let manager = ProfileManager::new(global_state_dir, 4)?;
    let now_ms = 1_700_000_000_000i64;
    manager.create_agent(agent_id, "profile-tool", now_ms)?;
    let embedding = vec![0.1; 4];
    manager.add_preference(
        agent_id,
        "Use docdex tools",
        &embedding,
        PreferenceCategory::Tooling,
        now_ms,
    )?;
    Ok(())
}

struct ServerHarness {
    child: Child,
}

impl ServerHarness {
    fn spawn(
        state_root: &Path,
        home_dir: &Path,
        repo_root: &Path,
        host: &str,
        port: u16,
        embedding_base_url: &str,
    ) -> Result<Self, Box<dyn Error>> {
        let repo_str = repo_root.to_string_lossy().to_string();
        let child = Command::new(docdex_bin())
            .env("DOCDEX_ENABLE_MEMORY", "0")
            .env("DOCDEX_STATE_DIR", state_root)
            .env("DOCDEX_ENABLE_MCP", "0")
            .env("HOME", home_dir)
            .args([
                "serve",
                "--repo",
                repo_str.as_str(),
                "--host",
                host,
                "--port",
                &port.to_string(),
                "--log",
                "warn",
                "--secure-mode=false",
                "--embedding-base-url",
                embedding_base_url,
                "--embedding-model",
                "fake-embed",
                "--embedding-timeout-ms",
                "200",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        wait_for_health(host, port)?;
        Ok(Self { child })
    }

    fn shutdown(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

struct McpHarness {
    child: Child,
    stdin: std::process::ChildStdin,
    reader: BufReader<std::process::ChildStdout>,
}

impl McpHarness {
    fn spawn(state_root: &Path, repo_root: &Path, base_url: &str) -> Result<Self, Box<dyn Error>> {
        let repo_str = repo_root.to_string_lossy().to_string();
        let mut cmd = Command::new(docdex_bin());
        cmd.env("DOCDEX_ENABLE_MEMORY", "0");
        cmd.env("DOCDEX_STATE_DIR", state_root);
        cmd.env("DOCDEX_HTTP_BASE_URL", base_url);
        cmd.env("DOCDEX_MCP_SERVER_BIN", mcp_server_bin());
        cmd.args(["mcp", "--repo", repo_str.as_str(), "--log", "warn"]);
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;

        let stdin = child.stdin.take().ok_or("failed to take mcp stdin")?;
        let stdout = child.stdout.take().ok_or("failed to take mcp stdout")?;
        Ok(Self {
            child,
            stdin,
            reader: BufReader::new(stdout),
        })
    }

    fn shutdown(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

fn send_line(
    stdin: &mut std::process::ChildStdin,
    payload: serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    let text = serde_json::to_string(&payload)?;
    stdin.write_all(text.as_bytes())?;
    stdin.write_all(b"\n")?;
    stdin.flush()?;
    Ok(())
}

fn read_line(
    reader: &mut BufReader<std::process::ChildStdout>,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line.trim().is_empty() {
        return Err("unexpected empty response line from MCP server".into());
    }
    Ok(serde_json::from_str(&line)?)
}

fn parse_tool_result(resp: &serde_json::Value) -> Result<serde_json::Value, Box<dyn Error>> {
    let content = resp
        .get("result")
        .and_then(|v| v.get("content"))
        .and_then(|v| v.as_array())
        .ok_or("tool result missing content array")?;
    let first_text = content
        .first()
        .and_then(|v| v.get("text"))
        .and_then(|v| v.as_str())
        .ok_or("tool result missing text content")?;
    Ok(serde_json::from_str(first_text)?)
}

#[test]
fn mcp_profile_tools_validate_category_and_response() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;

    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;
    let Some(mock) = MockOllama::spawn()? else {
        return Ok(());
    };

    let global_state_dir = home_dir.path().join(".docdex").join("state");
    write_config(home_dir.path(), &global_state_dir, &mock.base_url)?;
    seed_profile(&global_state_dir, "agent-profile")?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let base_url = format!("http://{host}:{port}");
    let mut server = ServerHarness::spawn(
        state_root.path(),
        home_dir.path(),
        repo.path(),
        host,
        port,
        &mock.base_url,
    )?;

    let mut mcp = McpHarness::spawn(state_root.path(), repo.path(), &base_url)?;
    let project_root = repo.path().to_string_lossy().to_string();

    send_line(
        &mut mcp.stdin,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "workspace_root": project_root, "agent_id": "agent-profile" }
        }),
    )?;
    let _init_resp = read_line(&mut mcp.reader)?;

    send_line(
        &mut mcp.stdin,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "docdex_save_preference",
                "arguments": { "content": "Bad category", "category": "invalid" }
            }
        }),
    )?;
    let invalid_resp = read_line(&mut mcp.reader)?;
    let error_code = invalid_resp
        .get("error")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.get("code"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(error_code, "invalid_argument");

    send_line(
        &mut mcp.stdin,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "docdex_get_profile",
                "arguments": {}
            }
        }),
    )?;
    let profile_resp = read_line(&mut mcp.reader)?;
    let profile_payload: Value = parse_tool_result(&profile_resp)?;
    let agents = profile_payload
        .get("agents")
        .and_then(|v| v.as_array())
        .map(|v| v.as_slice())
        .unwrap_or(&[]);
    assert!(agents.iter().any(|agent| {
        agent
            .get("id")
            .and_then(|v| v.as_str())
            .map(|id| id == "agent-profile")
            .unwrap_or(false)
    }));

    mcp.shutdown();
    server.shutdown();
    Ok(())
}
