mod common;

use serde_json::{json, Value};
use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Barrier};
use std::thread;
use tempfile::TempDir;

type BoxError = Box<dyn Error + Send + Sync>;

fn docdex_bin() -> PathBuf {
    std::env::set_var("DOCDEX_CLI_LOCAL", "1");
    std::env::set_var("DOCDEX_WEB_ENABLED", "0");
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

struct McpHarness {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    reader: BufReader<std::process::ChildStdout>,
}

impl McpHarness {
    fn spawn(repo: &Path, state_dir: &Path, lock_path: &Path) -> Result<Self, BoxError> {
        let repo_str = repo.to_string_lossy().to_string();
        let mut cmd = Command::new(docdex_bin());
        cmd.env("DOCDEX_WEB_ENABLED", "0");
        cmd.env("DOCDEX_ENABLE_MEMORY", "0");
        cmd.env("DOCDEX_DISABLE_DAEMON_AUTO", "1");
        cmd.env("DOCDEX_DAEMON_LOCK_PATH", lock_path);
        cmd.env_remove("DOCDEX_HTTP_BASE_URL");
        cmd.env(
            "DOCDEX_MCP_SERVER_BIN",
            state_dir.join("missing-docdex-mcp-server"),
        );
        cmd.args([
            "mcp",
            "--repo",
            repo_str.as_str(),
            "--log",
            "warn",
            "--state-dir",
            &state_dir.to_string_lossy(),
        ]);
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;

        let stdin = child
            .stdin
            .take()
            .ok_or("failed to take child stdin for MCP server")?;
        let stdout = child
            .stdout
            .take()
            .ok_or("failed to take child stdout for MCP server")?;
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

fn spawn_daemon(
    repo: &Path,
    state_dir: &Path,
    lock_path: &Path,
    port: u16,
) -> Result<std::process::Child, BoxError> {
    let repo_str = repo.to_string_lossy().to_string();
    let mut cmd = Command::new(docdex_bin());
    cmd.env("DOCDEX_WEB_ENABLED", "0");
    cmd.env("DOCDEX_ENABLE_MEMORY", "0");
    cmd.env("DOCDEX_ENABLE_MCP", "1");
    cmd.env("DOCDEX_DAEMON_LOCK_PATH", lock_path);
    cmd.args([
        "daemon",
        "--repo",
        repo_str.as_str(),
        "--state-dir",
        &state_dir.to_string_lossy(),
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--log",
        "warn",
        "--secure-mode=false",
    ]);
    let child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    common::wait_for_health("127.0.0.1", port).map_err(|err| {
        std::io::Error::new(std::io::ErrorKind::Other, err.to_string())
    })?;
    Ok(child)
}

fn run_docdex<I, S>(args: I, state_dir: &Path) -> Result<(), BoxError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let output = Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .args(args)
        .arg("--state-dir")
        .arg(state_dir)
        .output()?;
    if !output.status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "docdexd failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
        )
        .into());
    }
    Ok(())
}

fn write_repo(repo_root: &Path) -> Result<(), BoxError> {
    let docs_dir = repo_root.join("docs");
    std::fs::create_dir_all(&docs_dir)?;
    std::fs::write(
        docs_dir.join("alpha.md"),
        r#"# Alpha

ALPHA5E8F1C
"#,
    )?;
    std::fs::write(
        docs_dir.join("beta.md"),
        r#"# Beta

BETAC3D7A9
"#,
    )?;
    Ok(())
}

fn send_line(
    stdin: &mut std::process::ChildStdin,
    payload: serde_json::Value,
) -> Result<(), BoxError> {
    let text = serde_json::to_string(&payload)?;
    stdin.write_all(text.as_bytes())?;
    stdin.write_all(b"\n")?;
    stdin.flush()?;
    Ok(())
}

fn read_line(
    reader: &mut BufReader<std::process::ChildStdout>,
) -> Result<serde_json::Value, BoxError> {
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line.trim().is_empty() {
        return Err("unexpected empty response line from MCP server".into());
    }
    Ok(serde_json::from_str(&line)?)
}

fn parse_tool_result(resp: &Value) -> Result<Value, BoxError> {
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

fn run_search_and_open(
    mut harness: McpHarness,
    project_root: &str,
    query: &str,
    expected_path: &str,
    expected_token: &str,
) -> Result<(), BoxError> {
    let result = (|| -> Result<(), BoxError> {
        send_line(
            &mut harness.stdin,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "docdex_search",
                    "arguments": { "query": query, "limit": 5, "project_root": project_root }
                }
            }),
        )?;
        let search_resp = read_line(&mut harness.reader)?;
        let search_body = parse_tool_result(&search_resp)?;
        let hits = search_body
            .get("hits")
            .and_then(|v| v.as_array())
            .ok_or("docdex_search missing hits array")?;
        assert!(!hits.is_empty(), "expected at least one hit");
        let paths: Vec<String> = hits
            .iter()
            .filter_map(|hit| {
                hit.get("path")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .collect();
        assert!(
            paths.iter().all(|path| path == expected_path),
            "expected hits to resolve to {expected_path}; got {paths:?}"
        );

        send_line(
            &mut harness.stdin,
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "docdex_open",
                    "arguments": { "path": expected_path, "project_root": project_root }
                }
            }),
        )?;
        let open_resp = read_line(&mut harness.reader)?;
        let open_body = parse_tool_result(&open_resp)?;
        let content = open_body
            .get("content")
            .and_then(|v| v.as_str())
            .ok_or("docdex_open missing content")?;
        assert!(
            content.contains(expected_token),
            "expected docdex_open content to include token {expected_token}"
        );
        Ok(())
    })();

    harness.shutdown();
    result
}

#[test]
fn mcp_concurrency_same_repo_isolated() -> Result<(), BoxError> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;
    let state_dir = repo.path().join(".docdex-state");

    let repo_root = repo.path().to_string_lossy().to_string();
    run_docdex(["index", "--repo", repo_root.as_str()], &state_dir)?;

    let Some(port) = common::pick_free_port() else {
        return Ok(());
    };
    let lock_path = state_dir.join("daemon.lock");
    let mut daemon = spawn_daemon(repo.path(), &state_dir, &lock_path, port)?;

    let harness_a = McpHarness::spawn(repo.path(), &state_dir, &lock_path)?;
    let harness_b = McpHarness::spawn(repo.path(), &state_dir, &lock_path)?;

    let barrier = Arc::new(Barrier::new(3));
    let barrier_a = barrier.clone();
    let barrier_b = barrier.clone();

    let repo_project_root = repo_root.clone();
    let handle_a = thread::spawn(move || -> Result<(), BoxError> {
        barrier_a.wait();
        run_search_and_open(
            harness_a,
            repo_project_root.as_str(),
            "ALPHA5E8F1C",
            "docs/alpha.md",
            "ALPHA5E8F1C",
        )
    });
    let repo_project_root_b = repo_root.clone();
    let handle_b = thread::spawn(move || -> Result<(), BoxError> {
        barrier_b.wait();
        run_search_and_open(
            harness_b,
            repo_project_root_b.as_str(),
            "BETAC3D7A9",
            "docs/beta.md",
            "BETAC3D7A9",
        )
    });

    barrier.wait();

    handle_a.join().expect("alpha thread panicked")?;
    handle_b.join().expect("beta thread panicked")?;

    daemon.kill().ok();
    daemon.wait().ok();
    Ok(())
}
