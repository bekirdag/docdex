use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn docdex_bin() -> PathBuf {
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

struct McpHarness {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    reader: BufReader<std::process::ChildStdout>,
}

impl McpHarness {
    fn spawn(repo: &Path) -> Result<Self, Box<dyn Error>> {
        let repo_str = repo.to_string_lossy().to_string();
        let mut cmd = Command::new(docdex_bin());
        cmd.args([
            "mcp",
            "--repo",
            repo_str.as_str(),
            "--log",
            "warn",
            "--max-results",
            "4",
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

fn write_fixture_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    let docs_dir = repo_root.join("docs");
    std::fs::create_dir_all(&docs_dir)?;
    std::fs::write(
        docs_dir.join("overview.md"),
        r#"# Overview

This repository contains the MCP_ROADMAP notes used for testing.
"#,
    )?;
    // Extra files so limit clamping is observable.
    for i in 0..8 {
        std::fs::write(
            docs_dir.join(format!("extra_{i}.md")),
            format!("# Extra {i}\n\nMCP_ROADMAP term appears here.\n"),
        )?;
    }
    Ok(())
}

fn setup_repo() -> Result<TempDir, Box<dyn Error>> {
    let temp = TempDir::new()?;
    write_fixture_repo(temp.path())?;
    Ok(temp)
}

fn run_docdex<I, S>(args: I) -> Result<std::process::Output, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Ok(Command::new(docdex_bin()).args(args).output()?)
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

fn mcp_error_code(resp: &Value) -> Option<i64> {
    resp.get("error").and_then(|v| v.get("code")).and_then(|v| v.as_i64())
}

fn mcp_error_data_code(resp: &Value) -> Option<&str> {
    resp.get("error")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.get("code"))
        .and_then(|v| v.as_str())
}

fn pick_free_port() -> Option<u16> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener.local_addr().ok()?.port()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping HTTP tests: TCP bind not permitted in this environment");
            None
        }
        Err(err) => panic!("bind ephemeral port: {err}"),
    }
}

fn spawn_server(repo_root: &Path, host: &str, port: u16) -> Result<Child, Box<dyn Error>> {
    let repo_str = repo_root.to_string_lossy().to_string();
    Ok(Command::new(docdex_bin())
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
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?)
}

fn wait_for_health(host: &str, port: u16) -> Result<(), Box<dyn Error>> {
    let client = Client::builder().timeout(Duration::from_secs(1)).build()?;
    let url = format!("http://{host}:{port}/healthz");
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match client.get(&url).send() {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            _ => thread::sleep(Duration::from_millis(200)),
        }
    }
    Err("docdexd healthz endpoint did not respond in time".into())
}

#[test]
fn mcp_error_codes_match_http_invalid_query() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(["index", "--repo", repo_str.as_str()])?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = spawn_server(repo.path(), host, port)?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("http://{host}:{port}/search");
    let http_err: Value = client
        .get(&url)
        .query(&[("q", ""), ("limit", "1")])
        .send()?
        .json()?;
    assert_eq!(
        http_err
            .get("error")
            .and_then(|v| v.get("code"))
            .and_then(|v| v.as_str()),
        Some("invalid_query"),
        "HTTP invalid query should return machine code invalid_query"
    );

    let mut mcp = McpHarness::spawn(repo.path())?;
    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "docdex_search", "arguments": { "query": "" } }
        }),
    )?;
    let resp = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&resp), Some(-32602));
    assert_eq!(
        mcp_error_data_code(&resp),
        Some("invalid_query"),
        "MCP invalid query should map to the same machine code as HTTP"
    );

    mcp.shutdown();
    server.kill().ok();
    server.wait().ok();
    Ok(())
}

#[test]
fn mcp_validation_errors_have_consistent_envelope() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let mut mcp = McpHarness::spawn(repo.path())?;

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": { "name": "docdex_files", "arguments": { "limit": "not-a-number" } }
        }),
    )?;
    let resp = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&resp), Some(-32602));
    assert_eq!(mcp_error_data_code(&resp), Some("invalid_params"));
    assert_eq!(
        resp.get("error")
            .and_then(|v| v.get("data"))
            .and_then(|v| v.get("tool"))
            .and_then(|v| v.as_str()),
        Some("docdex_files"),
        "validation errors should include tool name"
    );
    assert!(
        resp.get("error")
            .and_then(|v| v.get("data"))
            .and_then(|v| v.get("reason"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .contains("invalid type"),
        "validation errors should include a reason string"
    );

    let other_repo = TempDir::new()?;
    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "docdex_search",
                "arguments": {
                    "query": "MCP_ROADMAP",
                    "project_root": other_repo.path().to_string_lossy()
                }
            }
        }),
    )?;
    let mismatch = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&mismatch), Some(-32602));
    assert_eq!(
        mcp_error_data_code(&mismatch),
        Some("unknown_repo"),
        "repo mismatches should be machine-coded as unknown_repo"
    );

    mcp.shutdown();
    Ok(())
}

#[test]
fn mcp_limit_and_max_content_enforcement_is_predictable() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(["index", "--repo", repo_str.as_str()])?;

    let mut mcp = McpHarness::spawn(repo.path())?;

    // Clamp docdex_search to max-results (4).
    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 20,
            "method": "tools/call",
            "params": {
                "name": "docdex_search",
                "arguments": { "query": "MCP_ROADMAP", "limit": 999 }
            }
        }),
    )?;
    let search_resp = read_line(&mut mcp.reader)?;
    let search_body = parse_tool_result(&search_resp)?;
    assert_eq!(
        search_body.get("limit").and_then(|v| v.as_u64()),
        Some(4),
        "docdex_search should report the clamped limit"
    );
    let hits_len = search_body
        .get("hits")
        .and_then(|v| v.as_array())
        .map(|v| v.len())
        .unwrap_or(0);
    assert!(hits_len <= 4, "docdex_search hits should not exceed max-results");

    // Clamp docdex_files to max (1000) even if request is larger.
    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 21,
            "method": "tools/call",
            "params": {
                "name": "docdex_files",
                "arguments": { "limit": 5000, "offset": 0 }
            }
        }),
    )?;
    let files_resp = read_line(&mut mcp.reader)?;
    let files_body = parse_tool_result(&files_resp)?;
    assert_eq!(
        files_body.get("limit").and_then(|v| v.as_u64()),
        Some(1000),
        "docdex_files should report the clamped limit"
    );

    // docdex_open should fail with a structured max-content error.
    let big_path = repo.path().join("docs").join("big.md");
    std::fs::write(&big_path, "x".repeat(600_000))?;
    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 22,
            "method": "tools/call",
            "params": { "name": "docdex_open", "arguments": { "path": "docs/big.md" } }
        }),
    )?;
    let open_err = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&open_err), Some(-32602));
    assert_eq!(mcp_error_data_code(&open_err), Some("max_content_exceeded"));
    assert_eq!(
        open_err.get("error")
            .and_then(|v| v.get("data"))
            .and_then(|v| v.get("details"))
            .and_then(|v| v.get("max_bytes"))
            .and_then(|v| v.as_u64()),
        Some(512 * 1024),
        "max_bytes should be reported"
    );

    mcp.shutdown();
    Ok(())
}

#[test]
fn cli_invalid_query_error_matches_machine_reason() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    let index_out = run_docdex(["index", "--repo", repo_str.as_str()])?;
    assert!(
        index_out.status.success(),
        "index should succeed: {}",
        String::from_utf8_lossy(&index_out.stderr)
    );

    let query_out = run_docdex([
        "query",
        "--repo",
        repo_str.as_str(),
        "--query",
        "",
        "--limit",
        "1",
    ])?;
    assert!(
        !query_out.status.success(),
        "empty query should fail in CLI query command"
    );
    let stderr = String::from_utf8_lossy(&query_out.stderr);
    assert!(
        stderr.contains("invalid query"),
        "CLI should report invalid query: {stderr}"
    );
    Ok(())
}

