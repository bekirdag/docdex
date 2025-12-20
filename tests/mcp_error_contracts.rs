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
        Self::spawn_with_options(repo, &[], None, 4)
    }

    fn spawn_with_env(
        repo: &Path,
        envs: &[(&str, &str)],
    ) -> Result<Self, Box<dyn Error>> {
        Self::spawn_with_options(repo, envs, None, 4)
    }

    fn spawn_with_options(
        repo: &Path,
        envs: &[(&str, &str)],
        state_dir: Option<&Path>,
        max_results: usize,
    ) -> Result<Self, Box<dyn Error>> {
        let repo_str = repo.to_string_lossy().to_string();
        let max_results = max_results.max(1).to_string();
        let mut cmd = Command::new(docdex_bin());
        cmd.args([
            "mcp",
            "--repo",
            repo_str.as_str(),
            "--log",
            "warn",
            "--max-results",
            max_results.as_str(),
        ]);
        if let Some(state_dir) = state_dir {
            let state_dir = state_dir.to_string_lossy().to_string();
            cmd.args(["--state-dir", state_dir.as_str()]);
        }
        for (key, value) in envs {
            cmd.env(key, value);
        }
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

fn write_repo_with_tokens(
    repo_root: &Path,
    unique_token: &str,
    common_token: &str,
    extra_common_files: usize,
) -> Result<(), Box<dyn Error>> {
    let docs_dir = repo_root.join("docs");
    std::fs::create_dir_all(&docs_dir)?;
    std::fs::write(
        docs_dir.join("unique.md"),
        format!(
            "# Unique\n\n{unique_token}\n\n{common_token}\n",
            unique_token = unique_token,
            common_token = common_token
        ),
    )?;
    for i in 0..extra_common_files {
        std::fs::write(
            docs_dir.join(format!("common_{i}.md")),
            format!("# Common {i}\n\n{common_token}\n", common_token = common_token),
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

fn index_repo_with_state(repo: &Path, state_dir: &Path) -> Result<(), Box<dyn Error>> {
    let repo_str = repo.to_string_lossy().to_string();
    let state_str = state_dir.to_string_lossy().to_string();
    let out = run_docdex([
        "index",
        "--repo",
        repo_str.as_str(),
        "--state-dir",
        state_str.as_str(),
    ])?;
    if !out.status.success() {
        return Err(format!(
            "index failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(())
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

fn parse_cli_json(raw: &[u8]) -> Result<serde_json::Value, Box<dyn Error>> {
    let text = String::from_utf8_lossy(raw);
    let trimmed = text.trim();
    Ok(serde_json::from_str(trimmed)?)
}

fn parse_cli_error(raw: &[u8]) -> Result<serde_json::Value, Box<dyn Error>> {
    parse_cli_json(raw)
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

#[test]
fn mcp_rate_limit_errors_include_retry_hints() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(["index", "--repo", repo_str.as_str()])?;

    let mut mcp = McpHarness::spawn_with_env(
        repo.path(),
        &[
            // 1 request/sec refill + burst=1 lets us deterministically rate-limit
            // multiple tools within a short test window.
            ("DOCDEX_MCP_RATE_LIMIT_PER_MIN", "60"),
            ("DOCDEX_MCP_RATE_LIMIT_BURST", "1"),
        ],
    )?;

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "docdex_search", "arguments": { "query": "MCP_ROADMAP", "limit": 1 } }
        }),
    )?;
    let ok = read_line(&mut mcp.reader)?;
    assert!(ok.get("result").is_some(), "first tool call should succeed");

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "docdex_files", "arguments": {} }
        }),
    )?;
    let limited_files = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&limited_files), Some(-32029));
    assert_eq!(mcp_error_data_code(&limited_files), Some("rate_limited"));

    let data_files = limited_files
        .get("error")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.as_object())
        .ok_or("rate-limit error missing error.data object")?;
    assert_eq!(
        data_files.get("limit_key").and_then(|v| v.as_str()),
        Some("mcp_tools")
    );
    assert_eq!(
        data_files.get("scope").and_then(|v| v.as_str()),
        Some("global")
    );
    assert!(
        data_files
            .get("retry_after_ms")
            .and_then(|v| v.as_u64())
            .is_some(),
        "retry_after_ms must be an integer"
    );
    assert!(
        data_files.keys().all(|k| {
            matches!(
                k.as_str(),
                "code" | "retry_after_ms" | "retry_at" | "limit_key" | "scope"
            )
        }),
        "error.data should only include stable keys"
    );

    // Wait long enough for the limiter to refill 1 token (per_minute=60).
    thread::sleep(Duration::from_millis(1100));

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": "docdex_files", "arguments": {} }
        }),
    )?;
    let ok_files = read_line(&mut mcp.reader)?;
    assert!(
        ok_files.get("result").is_some(),
        "docdex_files should succeed after refill"
    );

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": { "name": "docdex_search", "arguments": { "query": "MCP_ROADMAP", "limit": 1 } }
        }),
    )?;
    let limited_search = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&limited_search), Some(-32029));
    assert_eq!(mcp_error_data_code(&limited_search), Some("rate_limited"));

    let data_search = limited_search
        .get("error")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.as_object())
        .ok_or("rate-limit error missing error.data object (docdex_search)")?;

    fn shape_signature(data: &serde_json::Map<String, Value>) -> Vec<(String, &'static str)> {
        let mut out: Vec<(String, &'static str)> = data
            .iter()
            .map(|(k, v)| {
                let kind = match v {
                    Value::Null => "null",
                    Value::Bool(_) => "bool",
                    Value::Number(_) => "number",
                    Value::String(_) => "string",
                    Value::Array(_) => "array",
                    Value::Object(_) => "object",
                };
                (k.clone(), kind)
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    assert_eq!(
        shape_signature(data_files),
        shape_signature(data_search),
        "rate-limit error schema should be identical across tools sharing the limiter"
    );

    mcp.shutdown();
    Ok(())
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
    spawn_server_with_options(repo_root, host, port, None, None)
}

fn spawn_server_with_options(
    repo_root: &Path,
    host: &str,
    port: u16,
    state_dir: Option<&Path>,
    max_limit: Option<usize>,
) -> Result<Child, Box<dyn Error>> {
    let repo_str = repo_root.to_string_lossy().to_string();
    let mut cmd = Command::new(docdex_bin());
    cmd.args([
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
    ]);
    if let Some(state_dir) = state_dir {
        let state_dir = state_dir.to_string_lossy().to_string();
        cmd.args(["--state-dir", state_dir.as_str()]);
    }
    if let Some(max_limit) = max_limit {
        let max_limit = max_limit.max(1).to_string();
        cmd.args(["--max-limit", max_limit.as_str()]);
    }
    Ok(cmd.stdout(Stdio::null()).stderr(Stdio::null()).spawn()?)
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
    let details = mismatch
        .get("error")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.get("details"))
        .ok_or("mismatch error should include details")?;
    let expected = repo
        .path()
        .canonicalize()
        .unwrap_or_else(|_| repo.path().to_path_buf())
        .to_string_lossy()
        .replace('\\', "/");
    assert_eq!(
        details.get("knownCanonicalPath").and_then(|v| v.as_str()),
        Some(expected.as_str()),
        "mismatch details should include known canonical path"
    );
    let steps = details
        .get("recoverySteps")
        .and_then(|v| v.as_array())
        .ok_or("mismatch details should include recoverySteps array")?;
    assert!(!steps.is_empty(), "mismatch details should include recovery steps");
    assert!(
        steps.iter().any(|v| v
            .as_str()
            .unwrap_or_default()
            .contains("docdexd mcp --repo")),
        "expected recoverySteps to mention restarting the MCP server with `docdexd mcp --repo`; got: {details}"
    );

    mcp.shutdown();
    Ok(())
}

#[test]
fn mcp_missing_project_root_path_is_missing_repo_path() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let mut mcp = McpHarness::spawn(repo.path())?;

    let missing = repo.path().join("does-not-exist");
    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "docdex_search",
                "arguments": {
                    "query": "MCP_ROADMAP",
                    "project_root": missing.to_string_lossy()
                }
            }
        }),
    )?;
    let resp = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&resp), Some(-32602));
    assert_eq!(mcp_error_data_code(&resp), Some("missing_repo_path"));
    let details = resp
        .get("error")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.get("details"))
        .ok_or("missing repo path error should include details")?;
    let expected = missing.to_string_lossy().replace('\\', "/");
    assert_eq!(
        details.get("normalizedPath").and_then(|v| v.as_str()),
        Some(expected.as_str())
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

#[test]
fn cli_missing_vs_stale_index_errors_are_distinct_and_actionable() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo_with_tokens(repo.path(), "repo_token", "COMMON_TERM", 1)?;
    let repo_str = repo.path().to_string_lossy().to_string();

    let missing_out = run_docdex([
        "query",
        "--repo",
        repo_str.as_str(),
        "--query",
        "COMMON_TERM",
        "--limit",
        "1",
    ])?;
    assert!(
        !missing_out.status.success(),
        "missing index should fail"
    );
    let missing_payload = parse_cli_error(&missing_out.stderr)?;
    assert_eq!(
        missing_payload
            .get("error")
            .and_then(|v| v.get("code"))
            .and_then(|v| v.as_str()),
        Some("missing_index")
    );
    let missing_message = missing_payload
        .get("error")
        .and_then(|v| v.get("message"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_lowercase();
    assert!(
        missing_message.contains("docdexd index") || missing_message.contains("docdex_index"),
        "missing index should include remediation hint: {missing_message}"
    );

    let state_dir = repo.path().join(".docdex").join("index");
    std::fs::create_dir_all(&state_dir)?;
    let stale_out = run_docdex([
        "query",
        "--repo",
        repo_str.as_str(),
        "--query",
        "COMMON_TERM",
        "--limit",
        "1",
    ])?;
    assert!(
        !stale_out.status.success(),
        "stale index should fail"
    );
    let stale_payload = parse_cli_error(&stale_out.stderr)?;
    assert_eq!(
        stale_payload
            .get("error")
            .and_then(|v| v.get("code"))
            .and_then(|v| v.as_str()),
        Some("stale_index")
    );
    let stale_message = stale_payload
        .get("error")
        .and_then(|v| v.get("message"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_lowercase();
    assert!(
        stale_message.contains("docdexd index") || stale_message.contains("docdex_index"),
        "stale index should include remediation hint: {stale_message}"
    );

    Ok(())
}

#[test]
fn cli_search_is_repo_isolated_and_respects_limit() -> Result<(), Box<dyn Error>> {
    let workspace = TempDir::new()?;
    let state_root = TempDir::new()?;
    let repo_a = workspace.path().join("repo-a");
    let repo_b = workspace.path().join("repo-b");
    write_repo_with_tokens(&repo_a, "repo_a_token", "COMMON_TERM", 6)?;
    write_repo_with_tokens(&repo_b, "repo_b_token", "OTHER_TERM", 0)?;

    index_repo_with_state(&repo_a, state_root.path())?;
    index_repo_with_state(&repo_b, state_root.path())?;

    let repo_a_str = repo_a.to_string_lossy().to_string();
    let state_root_str = state_root.path().to_string_lossy().to_string();

    let isolate_out = run_docdex([
        "query",
        "--repo",
        repo_a_str.as_str(),
        "--state-dir",
        state_root_str.as_str(),
        "--query",
        "repo_b_token",
        "--limit",
        "5",
        "--repo-only",
    ])?;
    assert!(isolate_out.status.success(), "repo query should succeed");
    let isolate_payload = parse_cli_json(&isolate_out.stdout)?;
    let isolate_hits = isolate_payload
        .get("hits")
        .and_then(|v| v.as_array())
        .ok_or("CLI search missing hits array")?;
    assert!(
        isolate_hits.is_empty(),
        "repo-scoped CLI query must not return cross-repo hits"
    );

    let limit_out = run_docdex([
        "query",
        "--repo",
        repo_a_str.as_str(),
        "--state-dir",
        state_root_str.as_str(),
        "--query",
        "COMMON_TERM",
        "--limit",
        "3",
        "--repo-only",
    ])?;
    assert!(limit_out.status.success(), "repo query should succeed");
    let limit_payload = parse_cli_json(&limit_out.stdout)?;
    let limit_hits_len = limit_payload
        .get("hits")
        .and_then(|v| v.as_array())
        .map(|v| v.len())
        .unwrap_or(0);
    assert!(
        limit_hits_len <= 3,
        "CLI limit should cap results"
    );

    Ok(())
}

#[test]
fn mcp_search_is_repo_isolated_and_respects_max_results() -> Result<(), Box<dyn Error>> {
    let workspace = TempDir::new()?;
    let state_root = TempDir::new()?;
    let repo_a = workspace.path().join("repo-a");
    let repo_b = workspace.path().join("repo-b");
    write_repo_with_tokens(&repo_a, "repo_a_token", "COMMON_TERM", 6)?;
    write_repo_with_tokens(&repo_b, "repo_b_token", "OTHER_TERM", 0)?;

    index_repo_with_state(&repo_a, state_root.path())?;
    index_repo_with_state(&repo_b, state_root.path())?;

    let mut mcp =
        McpHarness::spawn_with_options(&repo_a, &[], Some(state_root.path()), 3)?;

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 30,
            "method": "tools/call",
            "params": {
                "name": "docdex_search",
                "arguments": { "query": "repo_b_token", "limit": 5 }
            }
        }),
    )?;
    let isolate_resp = read_line(&mut mcp.reader)?;
    let isolate_body = parse_tool_result(&isolate_resp)?;
    let isolate_hits = isolate_body
        .get("hits")
        .and_then(|v| v.as_array())
        .ok_or("MCP search missing hits array")?;
    assert!(
        isolate_hits.is_empty(),
        "repo-scoped MCP query must not return cross-repo hits"
    );

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tools/call",
            "params": {
                "name": "docdex_search",
                "arguments": { "query": "COMMON_TERM", "limit": 999 }
            }
        }),
    )?;
    let limit_resp = read_line(&mut mcp.reader)?;
    let limit_body = parse_tool_result(&limit_resp)?;
    assert_eq!(
        limit_body.get("limit").and_then(|v| v.as_u64()),
        Some(3),
        "MCP should report the clamped limit"
    );
    let limit_hits_len = limit_body
        .get("hits")
        .and_then(|v| v.as_array())
        .map(|v| v.len())
        .unwrap_or(0);
    assert!(
        limit_hits_len <= 3,
        "MCP max results should cap returned hits"
    );

    mcp.shutdown();
    Ok(())
}

#[test]
fn http_search_is_repo_isolated_and_respects_max_limit() -> Result<(), Box<dyn Error>> {
    let workspace = TempDir::new()?;
    let state_root = TempDir::new()?;
    let repo_a = workspace.path().join("repo-a");
    let repo_b = workspace.path().join("repo-b");
    write_repo_with_tokens(&repo_a, "repo_a_token", "COMMON_TERM", 6)?;
    write_repo_with_tokens(&repo_b, "repo_b_token", "OTHER_TERM", 0)?;

    index_repo_with_state(&repo_a, state_root.path())?;
    index_repo_with_state(&repo_b, state_root.path())?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = spawn_server_with_options(
        &repo_a,
        host,
        port,
        Some(state_root.path()),
        Some(3),
    )?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("http://{host}:{port}/search");
    let isolate_resp: Value = client
        .get(&url)
        .query(&[("q", "repo_b_token"), ("limit", "5"), ("snippets", "false")])
        .send()?
        .json()?;
    let isolate_hits = isolate_resp
        .get("hits")
        .and_then(|v| v.as_array())
        .ok_or("HTTP search missing hits array")?;
    assert!(
        isolate_hits.is_empty(),
        "repo-scoped HTTP query must not return cross-repo hits"
    );

    let limit_resp: Value = client
        .get(&url)
        .query(&[("q", "COMMON_TERM"), ("limit", "999"), ("snippets", "false")])
        .send()?
        .json()?;
    let limit_hits_len = limit_resp
        .get("hits")
        .and_then(|v| v.as_array())
        .map(|v| v.len())
        .unwrap_or(0);
    assert!(
        limit_hits_len <= 3,
        "HTTP max_limit should cap results"
    );

    server.kill().ok();
    server.wait().ok();
    Ok(())
}
